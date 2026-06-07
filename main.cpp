#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

bool commandExists(const std::string &name) {
    std::string check = "where " + name + " >nul 2>nul";
    return std::system(check.c_str()) == 0;
}

bool fileExists(const std::string &path) {
    std::ifstream file(path);
    return file.good();
}

std::string trim(const std::string &value);

bool loadConfigFromFile(const std::string &path, std::string &ip, std::string &port, std::string &user, std::string &password) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    std::vector<std::string> values;
    while (std::getline(file, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed.rfind("#", 0) == 0 || trimmed.rfind(";", 0) == 0) {
            continue;
        }

        size_t pos = trimmed.find('=');
        if (pos != std::string::npos) {
            std::string key = trim(trimmed.substr(0, pos));
            std::string value = trim(trimmed.substr(pos + 1));
            if (key == "ip" || key == "host" || key == "hostname") {
                ip = value;
            } else if (key == "port") {
                port = value;
            } else if (key == "user" || key == "username") {
                user = value;
            } else if (key == "pass" || key == "password") {
                password = value;
            }
        } else {
            values.push_back(trimmed);
        }
    }

    if (ip.empty() && values.size() >= 1) ip = values[0];
    if (port.empty() && values.size() >= 2) port = values[1];
    if (user.empty() && values.size() >= 3) user = values[2];
    if (password.empty() && values.size() >= 4) password = values[3];

    return !ip.empty() && !user.empty();
}

std::string trim(const std::string &value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        start++;
    }
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        end--;
    }
    return value.substr(start, end - start);
}

int captureCommandOutput(const std::string &command, std::string &output) {
    output.clear();
    FILE *pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return -1;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    int status = _pclose(pipe);
    return status;
}

bool parsePlinkHostKey(const std::string &output, std::string &hostkey) {
    std::istringstream stream(output);
    std::string line;

    while (std::getline(stream, line)) {
        std::string trimmed = trim(line);
        if (trimmed.rfind("ssh-", 0) == 0) {
            hostkey = trimmed;
            return true;
        }
    }
    return false;
}

std::string escapeForCmd(const std::string &value) {
    std::string escaped;
    for (char c : value) {
        if (c == '"') {
            escaped += "\\\"";
        } else {
            escaped += c;
        }
    }
    return escaped;
}

bool outputIndicatesPlinkHostKeyPrompt(const std::string &output) {
    std::string lower = output;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
    return lower.find("host key is not cached") != std::string::npos
        || lower.find("store key in cache") != std::string::npos
        || lower.find("press return") != std::string::npos
        || lower.find("if you trust this host") != std::string::npos;
}

int probePlinkHostKey(const std::string &ip, const std::string &port, const std::string &user, const std::string &password, std::string &hostkey, std::string &output) {
    std::string command = "plink.exe -ssh -batch -P " + port + " " + user + "@" + ip + " -pw \"" + password + "\" exit 2>&1";
    return captureCommandOutput(command, output);
}

std::string buildPlinkCommand(const std::string &ip, const std::string &port, const std::string &user, const std::string &password, const std::string &remoteCommand, const std::string &hostkey, bool acceptHostKeyPrompt) {
    std::string command = "plink.exe -ssh ";
    if (!hostkey.empty()) {
        command += "-batch ";
    }
    command += "-P " + port + " " + user + "@" + ip + " -pw \"" + password + "\"";
    if (!hostkey.empty()) {
        command += " -hostkey \"" + escapeForCmd(hostkey) + "\"";
    }
    command += " \"" + escapeForCmd(remoteCommand) + "\"";
    if (acceptHostKeyPrompt && hostkey.empty()) {
        command = "echo y|" + command;
    }
    return command;
}

bool executeRemoteCommand(const std::string &command) {
    int result = std::system(command.c_str());
    return result == 0;
}

bool executeCommandList(const std::string &ip, const std::string &port, const std::string &user, const std::string &password, const std::string &hostkey, bool acceptHostKeyPrompt) {
    std::vector<std::string> commands;
    commands.push_back("apt update && apt upgrade -y");
    commands.push_back("apt install curl net-tools nano -y");
    commands.push_back(
        "printf '%s\\n' "
        "'net.core.default_qdisc = cake' "
        "'net.ipv4.tcp_congestion_control = bbr' "
        "'net.core.rmem_max = 134217728' "
        "'net.core.wmem_max = 134217728' "
        "'net.ipv4.tcp_rmem = 4096 87380 134217728' "
        "'net.ipv4.tcp_wmem = 4096 65536 134217728' "
        "'net.ipv4.tcp_mem = 134217728 134217728 268435456' "
        "'net.core.somaxconn = 16384' "
        "'net.core.netdev_max_backlog = 32768' "
        "'net.ipv4.tcp_max_syn_backlog = 16384' "
        "'net.ipv4.tcp_mtu_probing = 1' "
        "'net.ipv4.tcp_low_latency = 1' "
        "'net.ipv4.tcp_tw_reuse = 1' "
        "'net.ipv4.tcp_fin_timeout = 15' "
        "'net.ipv4.tcp_notsent_lowat = 16384' "
        "'net.ipv4.tcp_no_metrics_save = 1' "
        "'net.ipv4.tcp_autocorking = 0' "
        "'net.core.netdev_budget = 800' "
        "'net.core.busy_poll = 50' "
        "'net.core.busy_read = 50' "
        "'net.ipv6.conf.all.disable_ipv6 = 1' "
        "'net.ipv6.conf.default.disable_ipv6 = 1' "
        "'net.ipv6.conf.lo.disable_ipv6 = 1' "
        "> /etc/sysctl.d/99-bbr.conf"
    );
    commands.push_back("sysctl --system");
    commands.push_back("modprobe tcp_bbr");
    commands.push_back("echo \"tcp_bbr\" >> /etc/modules-load.d/modules.conf");
    commands.push_back("reboot");

    for (const auto &remoteCommand : commands) {
        std::cout << "Executing remote command: " << remoteCommand << "\n";
        std::string plinkCommand = buildPlinkCommand(ip, port, user, password, remoteCommand, hostkey, acceptHostKeyPrompt);
        bool ok = executeRemoteCommand(plinkCommand);
        if (!ok && remoteCommand != "reboot") {
            return false;
        }
    }
    return true;
}

bool downloadPlink() {
    const std::string url = "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe";
    const std::string target = "plink.exe";

    if (fileExists(target)) {
        return true;
    }

    if (commandExists("powershell") || commandExists("pwsh")) {
        std::string shell = commandExists("powershell") ? "powershell" : "pwsh";
        std::string command = shell + " -NoProfile -Command \"Invoke-WebRequest -Uri '" + url + "' -OutFile './" + target + "' -UseBasicParsing\"";
        if (std::system(command.c_str()) == 0 && fileExists(target)) {
            return true;
        }
    }

    if (commandExists("curl")) {
        std::string command = "curl -L -o \"" + target + "\" \"" + url + "\"";
        if (std::system(command.c_str()) == 0 && fileExists(target)) {
            return true;
        }
    }

    return false;
}

int main() {
    std::string ip;
    std::string port;
    std::string user;
    std::string password;

    const std::string configFile = "vds_config.txt";
    std::cout << "VDS SSH connector\n";
    std::cout << "----------------\n";

    if (fileExists(configFile)) {
        std::cout << "Loading connection data from " << configFile << "...\n";
        if (!loadConfigFromFile(configFile, ip, port, user, password)) {
            std::cerr << "Config file found but invalid. Please check " << configFile << ".\n";
            return 1;
        }
    } else {
        std::cout << "Enter server IP or hostname: ";
        std::getline(std::cin, ip);
        std::cout << "Enter SSH port (default 22): ";
        std::getline(std::cin, port);
        std::cout << "Enter username: ";
        std::getline(std::cin, user);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
    }

    if (ip.empty() || user.empty()) {
        std::cerr << "IP and username are required.\n";
        return 1;
    }

    if (port.empty()) {
        port = "22";
    }

    bool hasPlink = commandExists("plink");
    bool hasSsh = commandExists("ssh");
    int result = 1;

    if (!hasPlink && !hasSsh) {
        std::cout << "\nNo SSH client found. Attempting to download plink.exe...\n";
        if (downloadPlink()) {
            std::cout << "plink.exe downloaded successfully.\n";
            hasPlink = true;
        } else {
            std::cout << "Failed to download plink.exe.\n";
            std::cout << "Please install PuTTY/Plink or Windows OpenSSH client manually.\n";
        }
    }

    std::string plinkHostKey;
    std::string probeOutput;
    bool plinkHostKeyFound = false;
    bool acceptHostKeyPrompt = false;

    if (hasPlink) {
        probePlinkHostKey(ip, port, user, password, plinkHostKey, probeOutput);
        plinkHostKeyFound = parsePlinkHostKey(probeOutput, plinkHostKey);
        acceptHostKeyPrompt = !plinkHostKeyFound;

        result = executeCommandList(ip, port, user, password, plinkHostKeyFound ? plinkHostKey : std::string(), acceptHostKeyPrompt) ? 0 : 1;
    } else if (hasSsh) {
        std::cout << "\nPlink not found. Connecting with built-in ssh...\n";
        std::cout << "Command execution via ssh is not implemented in this version.\n";
        result = 1;
    }

    if (result == 0) {
        std::cout << "\nRemote command sequence finished successfully.\n";
    } else if (hasPlink || hasSsh) {
        std::cout << "\nRemote command sequence failed.\n";
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    return result;
}
