import time
import ping3
import argparse
import json
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
        except PermissionError:
            return {"error": "Permission denied. Try running the script with elevated privileges (e.g., sudo)."}
        except Exception as e:
            return {"error": f"Error pinging {target}: {e}"}
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
            return {"error": "Permission denied. Try running the script with elevated privileges (e.g., sudo)."}
        except Exception as e:
            return {"error": f"Error pinging {target}: {e}"}
    return ((count - successful) / count) * 100

def main(target, count=10):
    if not target:
        print(json.dumps({"error": "No target provided. Please enter a valid IP address or domain name."}))
        return

    result = {
        "target": target,
        "count": count
    }

    # Measure latency
    latencies = measure_latency(target, count)
    if isinstance(latencies, dict) and "error" in latencies:
        print(json.dumps(latencies))
        return

    if latencies and len(latencies) > 0:
        result["latency"] = {
            "min": f"{min(latencies):.2f} ms",
            "max": f"{max(latencies):.2f} ms",
            "avg": f"{mean(latencies):.2f} ms",
            "stddev": f"{stdev(latencies):.2f} ms" if len(latencies) > 1 else "0.00 ms"
        }
        # Calculate jitter
        result["jitter"] = f"{calculate_jitter(latencies):.2f} ms"
    else:
        result["latency"] = "No response"
        result["jitter"] = None

    # Measure packet loss
    packet_loss = measure_packet_loss(target, count)
    if isinstance(packet_loss, dict) and "error" in packet_loss:
        print(json.dumps(packet_loss))
        return
    result["packet loss"] = f"{packet_loss:.2f}%"  # formatted to .2f

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    # Set up argument parser with both positional and optional count
    parser = argparse.ArgumentParser(description="Network Performance Testing Tool")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("count", nargs='?', type=int, default=10, help="Number of pings to send (positional, default: 10)")
    parser.add_argument("-c", "--count", dest="count_flag", type=int, help="Number of pings to send (flag-style)")
    args = parser.parse_args()

    # Use flag-style count if provided, otherwise use positional count
    final_count = args.count_flag if args.count_flag is not None else args.count
    main(args.target, final_count)
