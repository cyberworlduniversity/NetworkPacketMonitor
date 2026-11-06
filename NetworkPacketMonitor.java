import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Network Packet Monitor
 * Captures and analyzes network packets in real-time.
 * Displays source/destination IP, protocol, packet size, and detects suspicious traffic.
 *
 * Author: hemanathan115
 * GitHub: https://github.com/hemanathan115
 */
public class NetworkPacketMonitor {

    // ── Statistics counters ──────────────────────────────────────────────────
    private static final AtomicLong tcpCount    = new AtomicLong(0);
    private static final AtomicLong udpCount    = new AtomicLong(0);
    private static final AtomicLong icmpCount   = new AtomicLong(0);
    private static final AtomicLong otherCount  = new AtomicLong(0);
    private static final AtomicLong totalBytes  = new AtomicLong(0);

    // Suspicious port list (common attack / malware ports)
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>(Arrays.asList(
            22, 23, 445, 3389, 4444, 5555, 6666, 7777, 8080, 9001
    ));

    // Bounded per-source sliding-window counters.
    private static final long RATE_WINDOW_MS = 10_000L;
    private static final long RATE_ENTRY_TTL_MS = 60_000L;
    private static final int MAX_TRACKED_IPS = 4096;
    private static final Map<String, RateWindow> ipPacketCount = new ConcurrentHashMap<>();

    static final class RateWindow {
        private long windowStart;
        private long lastSeen;
        private int count;

        RateWindow(long now) {
            windowStart = now;
            lastSeen = now;
        }

        synchronized int record(long now) {
            if (now - windowStart >= RATE_WINDOW_MS || now < windowStart) {
                windowStart = now;
                count = 0;
            }
            lastSeen = now;
            return ++count;
        }

        synchronized long lastSeen() { return lastSeen; }
        synchronized int count() { return count; }
    }

    static int recordSourcePacket(String sourceIp, long now) {
        RateWindow counter = ipPacketCount.get(sourceIp);
        if (counter == null) {
            if (ipPacketCount.size() >= MAX_TRACKED_IPS) pruneRateCounters(now);
            if (ipPacketCount.size() >= MAX_TRACKED_IPS) return 0;
            RateWindow fresh = new RateWindow(now);
            RateWindow previous = ipPacketCount.putIfAbsent(sourceIp, fresh);
            counter = previous == null ? fresh : previous;
        }
        return counter.record(now);
    }

    static void pruneRateCounters(long now) {
        ipPacketCount.entrySet().removeIf(entry ->
                now - entry.getValue().lastSeen() > RATE_ENTRY_TTL_MS);
    }

    // ── Entry point ─────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {

        // List available network interfaces
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs == null || allDevs.isEmpty()) {
            System.err.println("[ERROR] No network interfaces found. Run as root/administrator.");
            return;
        }

        System.out.println("=== Network Packet Monitor ===");
        System.out.println("Available interfaces:");
        for (int i = 0; i < allDevs.size(); i++) {
            System.out.printf("  [%d] %s – %s%n",
                    i,
                    allDevs.get(i).getName(),
                    allDevs.get(i).getDescription() != null
                            ? allDevs.get(i).getDescription()
                            : "No description");
        }

        // Default to non-promiscuous capture; broader capture requires explicit opt-in.
        int ifaceIndex = 0;
        boolean promiscuous = false;
        for (String arg : args) {
            if ("--promiscuous".equals(arg)) {
                promiscuous = true;
            } else {
                try {
                    ifaceIndex = Integer.parseInt(arg);
                } catch (NumberFormatException e) {
                    System.err.println("[ERROR] Usage: NetworkPacketMonitor [interface-index] [--promiscuous]");
                    return;
                }
            }
        }
        if (ifaceIndex < 0 || ifaceIndex >= allDevs.size()) {
            System.err.printf("[ERROR] Interface index must be between 0 and %d.%n", allDevs.size() - 1);
            return;
        }

        PcapNetworkInterface nif = allDevs.get(ifaceIndex);
        System.out.printf("%nCapturing on: %s%n", nif.getName());
        System.out.printf("Capture mode: %s%n", promiscuous ? "PROMISCUOUS (explicit opt-in)" : "NON-PROMISCUOUS");
        System.out.println("Press Ctrl+C to stop.\\n");

        PcapNetworkInterface.PromiscuousMode captureMode = promiscuous
                ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
        try (PcapHandle handle = nif.openLive(65536, captureMode, 10)) {
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
            try {
                scheduler.scheduleAtFixedRate(() -> {
                    pruneRateCounters(System.currentTimeMillis());
                    printStats();
                }, 10, 10, TimeUnit.SECONDS);

                handle.loop(-1, (RawPacketListener) rawPacket -> {
                    try {
                        Packet packet = EthernetPacket.newPacket(rawPacket, 0, rawPacket.length);
                        analyzePacket(packet, rawPacket.length);
                    } catch (Exception ignored) {
                        // Skip malformed or unsupported frames without terminating capture.
                    }
                });
            } finally {
                scheduler.shutdownNow();
            }
        }
    }

    // ── Packet analysis ─────────────────────────────────────────────────────
    private static void analyzePacket(Packet packet, int rawLength) {
        totalBytes.addAndGet(rawLength);

        String srcIp   = "N/A";
        String dstIp   = "N/A";
        String proto   = "OTHER";
        int    srcPort = -1;
        int    dstPort = -1;

        // Extract IP layer
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        IpV6Packet ipv6 = packet.get(IpV6Packet.class);

        if (ipv4 != null) {
            srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
        } else if (ipv6 != null) {
            srcIp = ipv6.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipv6.getHeader().getDstAddr().getHostAddress();
        } else {
            otherCount.incrementAndGet();
            return; // Non-IP traffic – skip detailed logging
        }

        // Extract transport layer
        TcpPacket tcp = packet.get(TcpPacket.class);
        UdpPacket udp = packet.get(UdpPacket.class);
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);

        if (tcp != null) {
            proto   = "TCP";
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            tcpCount.incrementAndGet();
        } else if (udp != null) {
            proto   = "UDP";
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
            udpCount.incrementAndGet();
        } else if (icmp != null) {
            proto = "ICMP";
            icmpCount.incrementAndGet();
        } else {
            proto = "OTHER";
            otherCount.incrementAndGet();
        }

        // Rate-limit tracking per source IP
        recordSourcePacket(srcIp, System.currentTimeMillis());

        // Print packet summary
        String suspicious = detectSuspicious(srcIp, dstPort);
        System.out.printf("[%s] %s → %s | Proto: %-5s | Size: %5d bytes%s%n",
                proto,
                formatAddr(srcIp, srcPort),
                formatAddr(dstIp, dstPort),
                proto,
                rawLength,
                suspicious);
    }

    // ── Suspicious traffic detection ────────────────────────────────────────
    private static String detectSuspicious(String srcIp, int dstPort) {
        StringBuilder warnings = new StringBuilder();

        // Flag suspicious destination ports
        if (SUSPICIOUS_PORTS.contains(dstPort)) {
            warnings.append(" ⚠ SUSPICIOUS PORT(").append(dstPort).append(")");
        }

        // Flag IPs sending more than 200 packets (simple flood heuristic)
        RateWindow count = ipPacketCount.get(srcIp);
        if (count != null && count.count() > 200) {
            warnings.append(" ⚠ HIGH PACKET RATE FROM ").append(srcIp);
        }

        return warnings.toString();
    }

    // ── Periodic statistics ─────────────────────────────────────────────────
    private static void printStats() {
        long total = tcpCount.get() + udpCount.get() + icmpCount.get() + otherCount.get();
        System.out.println("\n──────────── Traffic Statistics ────────────");
        System.out.printf("  Total packets : %,d%n", total);
        System.out.printf("  TCP           : %,d%n", tcpCount.get());
        System.out.printf("  UDP           : %,d%n", udpCount.get());
        System.out.printf("  ICMP          : %,d%n", icmpCount.get());
        System.out.printf("  Other         : %,d%n", otherCount.get());
        System.out.printf("  Total bytes   : %,d%n", totalBytes.get());
        System.out.println("────────────────────────────────────────────\n");
    }

    // ── Helpers ─────────────────────────────────────────────────────────────
    private static String formatAddr(String ip, int port) {
        return port >= 0 ? ip + ":" + port : ip;
    }
}
