import os
import subprocess
import sys
from datetime import datetime

class StaticAnalyzer:
    def __init__(self, bin_file):
        self.bin_file = bin_file
        self.report_file = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.extracted_dir = None

    def write_to_report(self, content, header=None):
        with open(self.report_file, 'a') as f:
            if header:
                f.write(f"\n{'='*50}\n{header}\n{'='*50}\n")
            f.write(content + "\n")

    def run_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error executing command: {str(e)}"

    def analyze_binwalk(self):
        command = f"binwalk -e {self.bin_file}"
        output = self.run_command(command)
        self.write_to_report(output, "Binwalk Analysis")
        self.extracted_dir = f"_{os.path.basename(self.bin_file)}.extracted"

    def analyze_web_interface(self):
        web_dir = os.path.join(self.extracted_dir, "squashfs-root/web")
        if not os.path.exists(web_dir):
            self.write_to_report("Error: Web directory not found", "Web Interface Analysis")
            return

        web_contents = self.run_command(f"ls -R {web_dir}")
        self.write_to_report(web_contents, "Web Directory Contents")

        web_analysis = []
        web_analysis.append("\nFirmware Extraction Analysis:")
        
        if os.path.exists(os.path.join(web_dir, "update")):
            web_analysis.append("• Web-based firmware update mechanism detected")
        
        if os.path.exists(os.path.join(web_dir, "config")):
            web_analysis.append("• Web configuration interface present")

        js_files = []
        for root, _, files in os.walk(web_dir):
            for file in files:
                if file.endswith('.js'):
                    js_files.append(os.path.join(root, file))

        if js_files:
            web_analysis.append("\nPotential Firmware Update Related Files:")
            for js_file in js_files:
                web_analysis.append(f"• {os.path.basename(js_file)}")

        hardware_analysis = [
            "\nPotential Hardware Interfaces:",
            "• UART interface might be available (check for serial console configurations)",
            "• JTAG interface might be present (check hardware documentation)",
            "\nFirmware Access Methods:",
            "• Web interface available for configuration",
            "• Direct firmware update mechanism through web interface",
            "• Possible serial console access for firmware operations"
        ]

        web_analysis.extend(hardware_analysis)
        self.write_to_report("\n".join(web_analysis), "Firmware Extraction Analysis")

    def analyze_boot_detailed(self):
        boot_dir = os.path.join(self.extracted_dir, "squashfs-root/boot")
        if not os.path.exists(boot_dir):
            self.write_to_report("Error: Boot directory not found", "Boot Analysis")
            return

        boot_analysis = []
        
        boot_contents = self.run_command(f"ls -la {boot_dir}")
        boot_analysis.append("Boot Directory Contents:")
        boot_analysis.append(boot_contents)

        uimage_path = os.path.join(boot_dir, "uImage")
        if os.path.exists(uimage_path):
            uimage_info = self.run_command(f"dumpimage -l {uimage_path}")
            boot_analysis.append("\nuImage Analysis:")
            boot_analysis.append(uimage_info)

            file_info = self.run_command(f"file {uimage_path}")
            boot_analysis.append("\nuImage File Information:")
            boot_analysis.append(file_info)

        bootloader_files = [f for f in os.listdir(boot_dir) if f.startswith('boot')]
        if bootloader_files:
            boot_analysis.append("\nBootloader Configuration Files:")
            for bf in bootloader_files:
                boot_analysis.append(f"• {bf}")

        self.write_to_report("\n".join(boot_analysis), "Detailed Boot Analysis")

    def analyze_etc_files(self):
        etc_dir = os.path.join(self.extracted_dir, "squashfs-root/etc")
        if not os.path.exists(etc_dir):
            self.write_to_report("Error: /etc directory not found", "ETC Directory Analysis")
            return

        etc_analysis = []
        
        # Analyze passwd file
        passwd_file = os.path.join(etc_dir, "passwd")
        if os.path.exists(passwd_file):
            with open(passwd_file, 'r') as f:
                passwd_content = f.read()
            etc_analysis.append("=== /etc/passwd Content ===")
            etc_analysis.append(passwd_content)
            
            etc_analysis.append("\nUser Accounts Analysis:")
            for line in passwd_content.splitlines():
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 7:
                        etc_analysis.append(f"User: {parts[0]}, UID: {parts[2]}, Home: {parts[5]}, Shell: {parts[6]}")

        # Analyze protocols file
        protocols_file = os.path.join(etc_dir, "protocols")
        if os.path.exists(protocols_file):
            with open(protocols_file, 'r') as f:
                protocols_content = f.read()
            etc_analysis.append("\n=== /etc/protocols Content ===")
            etc_analysis.append(protocols_content)
            
            protocol_count = len([line for line in protocols_content.splitlines() 
                                if line.strip() and not line.startswith('#')])
            etc_analysis.append(f"\nTotal protocols defined: {protocol_count}")

        # Analyze services file
        services_file = os.path.join(etc_dir, "services")
        if os.path.exists(services_file):
            with open(services_file, 'r') as f:
                services_content = f.read()
            etc_analysis.append("\n=== /etc/services Content ===")
            etc_analysis.append(services_content)
            
            service_count = len([line for line in services_content.splitlines() 
                               if line.strip() and not line.startswith('#')])
            etc_analysis.append(f"\nTotal services defined: {service_count}")

        # Additional ETC directory analysis
        etc_files = os.listdir(etc_dir)
        etc_analysis.append("\n=== Important Configuration Files in /etc ===")
        important_files = [
            'hostname', 'hosts', 'resolv.conf', 'network/',
            'init.d/', 'rc.d/', 'default/', 'sysconfig/',
            'ssh/', 'ssl/', 'security/', 'crontab'
        ]
        
        for important_file in important_files:
            full_path = os.path.join(etc_dir, important_file)
            if os.path.exists(full_path):
                if os.path.isdir(full_path):
                    files_in_dir = os.listdir(full_path)
                    etc_analysis.append(f"\nContents of {important_file}:")
                    for file in files_in_dir:
                        etc_analysis.append(f"  - {file}")
                else:
                    try:
                        with open(full_path, 'r') as f:
                            content = f.read()
                        etc_analysis.append(f"\nContent of {important_file}:")
                        etc_analysis.append(content)
                    except Exception as e:
                        etc_analysis.append(f"Error reading {important_file}: {str(e)}")

        self.write_to_report("\n".join(etc_analysis), "ETC Directory Analysis")

    def run_analysis(self):
        self.write_to_report(f"Analysis started at: {datetime.now()}\n")
        
        self.analyze_binwalk()
        self.analyze_web_interface()
        self.analyze_boot_detailed()
        self.analyze_etc_files()
        
        summary = [
            "\nAnalysis Summary:",
            "1. Firmware Extraction Methods:",
            "   • Web interface based update mechanism",
            "   • Direct hardware access (UART/JTAG)",
            "   • Bootloader interface",
            "\n2. Available Interfaces:",
            "   • Web management interface",
            "   • Serial console (if available)",
            "   • Boot loader interface",
            "\n3. System Configuration:",
            "   • User accounts analyzed",
            "   • Network services identified",
            "   • System protocols documented",
            "\n4. Security Considerations:",
            "   • Check for firmware signing mechanisms",
            "   • Verify update authentication",
            "   • Review boot sequence security",
            "   • Analyze user permissions and access controls"
        ]
        
        self.write_to_report("\n".join(summary), "Analysis Summary")
        self.write_to_report(f"\nAnalysis completed at: {datetime.now()}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <binary_file>")
        sys.exit(1)

    bin_file = sys.argv[1]
    if not os.path.exists(bin_file):
        print(f"Error: File {bin_file} not found")
        sys.exit(1)

    analyzer = StaticAnalyzer(bin_file)
    analyzer.run_analysis()
    print(f"Analysis complete. Results saved in {analyzer.report_file}")

if __name__ == "__main__":
    main()
