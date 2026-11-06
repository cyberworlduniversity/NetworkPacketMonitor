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

    // Simple rate-limit tracker: IP → packet count in the last window
    private static final Map<String, AtomicLong> ipPacketCount = new ConcurrentHashMap<>();

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

        // Use the first interface by default (or override via CLI arg)
        int ifaceIndex = 0;
        if (args.length > 0) {
            try { ifaceIndex = Integer.parseInt(args[0]); }
            catch (NumberFormatException ignored) {}
        }

        PcapNetworkInterface nif = allDevs.get(ifaceIndex);
        System.out.printf("%nCapturing on: %s%n", nif.getName());
        System.out.println("Press Ctrl+C to stop.\n");

        // Open the interface in promiscuous mode, 65536-byte snap length, 10 ms timeout
        try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {

            // Background thread: print stats every 10 seconds
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
            scheduler.scheduleAtFixedRate(NetworkPacketMonitor::printStats, 10, 10, TimeUnit.SECONDS);

            // Capture loop
            handle.loop(-1, (RawPacketListener) rawPacket -> {
                try {
                    Packet packet = EthernetPacket.newPacket(rawPacket, 0, rawPacket.length);
                    analyzePacket(packet, rawPacket.length);
                } catch (Exception e) {
                    // Silently skip malformed packets
                }
            });

            scheduler.shutdownNow();
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
        ipPacketCount.computeIfAbsent(srcIp, k -> new AtomicLong(0)).incrementAndGet();

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
        AtomicLong count = ipPacketCount.get(srcIp);
        if (count != null && count.get() > 200) {
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
