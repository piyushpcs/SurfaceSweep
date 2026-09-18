import argparse
from modules.extractor import run_extractor, save_report

def main():
    parser = argparse.ArgumentParser(description="SurfaceSweep — JS Endpoint Extractor")
    parser.add_argument("target", help="Target URL, e.g. https://example.com")
    parser.add_argument("-o", "--output", default="surfacesweep_report.json", help="Output JSON file")
    parser.add_argument("-t", "--threads", type=int, default=6, help="Concurrent fetch threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    result = run_extractor(args.target, threads=args.threads, verbose=not args.quiet)
    save_report(result, args.output)

if __name__ == "__main__":
    main()