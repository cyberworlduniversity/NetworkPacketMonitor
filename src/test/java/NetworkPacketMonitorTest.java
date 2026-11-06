import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NetworkPacketMonitorTest {
    @Test
    void rateCounterResetsAfterWindowExpires() {
        NetworkPacketMonitor.RateWindow counter = new NetworkPacketMonitor.RateWindow(1_000L);

        assertEquals(1, counter.record(1_000L));
        assertEquals(2, counter.record(5_000L));
        assertEquals(1, counter.record(11_000L));
    }

    @Test
    void rateCounterHandlesClockMovingBackwards() {
        NetworkPacketMonitor.RateWindow counter = new NetworkPacketMonitor.RateWindow(10_000L);

        assertEquals(1, counter.record(10_000L));
        assertEquals(1, counter.record(9_000L));
    }

    @Test
    void invalidInterfaceIndexIsRejectedByBoundsCheck() {
        int interfaceCount = 2;
        assertTrue(NetworkPacketMonitor.isValidInterfaceIndex(0, interfaceCount));
        assertTrue(NetworkPacketMonitor.isValidInterfaceIndex(1, interfaceCount));
        assertFalse(NetworkPacketMonitor.isValidInterfaceIndex(-1, interfaceCount));
        assertFalse(NetworkPacketMonitor.isValidInterfaceIndex(2, interfaceCount));
    }
}
