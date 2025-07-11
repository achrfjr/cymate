import time
import ping3
import argparse
from statistics import mean, stdev

def measure_latency(target, count=10):
    """
    Measure latency (round-trip time) to the target.
    Returns a list of latency values in milliseconds.
    """
    latencies = []
    for _ in range(count):
        try:
            latency = ping3.ping(target, unit='ms', timeout=1)  # Ping with a timeout of 1 second
            if latency is not None:
                latencies.append(latency)
            else:
                print(f"Request timed out for {target}")
        except PermissionError:
            print("Error: Permission denied. Try running the script with elevated privileges (e.g., sudo).")
            return None
        except Exception as e:
            print(f"Error pinging {target}: {e}")
            return None
    return latencies

def calculate_jitter(latencies):
    """
    Calculate jitter (variation in latency) from a list of latency values.
    """
    if len(latencies) < 2:
        return 0
    differences = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return mean(differences)

def measure_packet_loss(target, count=10):
    """
    Measure packet loss percentage by sending `count` pings.
    """
    successful = 0
    for _ in range(count):
        try:
            latency = ping3.ping(target, unit='ms', timeout=1)
            if latency is not None:
                successful += 1
        except PermissionError:
            print("Error: Permission denied. Try running the script with elevated privileges (e.g., sudo).")
            return None
        except Exception as e:
            print(f"Error pinging {target}: {e}")
            return None
    return ((count - successful) / count) * 100

def main(target, count=10):
    if not target:
        print("Error: No target provided. Please enter a valid IP address or domain name.")
        return

    print(f"Measuring network performance for {target}...\n")

    # Measure latency
    latencies = measure_latency(target, count)
    if latencies:
        print(f"Latency (Round-Trip Time):")
        print(f"  Min: {min(latencies):.2f} ms")
        print(f"  Max: {max(latencies):.2f} ms")
        print(f"  Avg: {mean(latencies):.2f} ms")
        print(f"  Std Dev: {stdev(latencies):.2f} ms\n")

        # Calculate jitter
        jitter = calculate_jitter(latencies)
        print(f"Jitter: {jitter:.2f} ms\n")

    # Measure packet loss
    packet_loss = measure_packet_loss(target, count)
    if packet_loss is not None:
        print(f"Packet Loss: {packet_loss:.2f}%\n")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Network Performance Testing Tool")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of pings to send (default: 10)")
    args = parser.parse_args()

    main(args.target, args.count)