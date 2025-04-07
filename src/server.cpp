#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <unordered_map>
#include <sstream>
#include <arpa/inet.h>

#define DEBUG_OUTPUT 1

#define DEBUG(x)      \
    if (DEBUG_OUTPUT) \
        std::cout << x << std::endl;

struct ResourceRecord
{
    std::string name;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    std::string rdata;

    int size() const
    {
        int nameSize = name.length() + 2; // +2 for label length bytes and null terminator
        for (char c : name)
        {
            if (c == '.')
                nameSize++; // Each dot becomes a label length byte
        }
        // 2 bytes for type, 2 bytes for class, 4 bytes for ttl, 2 bytes for rdlength
        return nameSize + 2 + 2 + 4 + 2 + rdlength;
    }

    // Serialize resource record into the buffer at given offset
    int serialize(char *buffer, int offset) const
    {
        // Write domain name in DNS format (length byte followed by characters)
        std::string name_copy = name;
        size_t pos = 0;
        size_t next;

        // Process each label (part between dots)
        while ((next = name_copy.find('.', pos)) != std::string::npos)
        {
            int labelLength = next - pos;
            buffer[offset++] = labelLength; // Label length

            // Copy the label characters
            for (int i = 0; i < labelLength; i++)
            {
                buffer[offset++] = name_copy[pos + i];
            }

            pos = next + 1; // Skip the dot
        }

        // Handle the last label (after the last dot or the entire name if no dots)
        int labelLength = name_copy.length() - pos;
        if (labelLength > 0)
        {
            buffer[offset++] = labelLength; // Label length

            // Copy the label characters
            for (int i = 0; i < labelLength; i++)
            {
                buffer[offset++] = name_copy[pos + i];
            }
        }

        // Add null byte to terminate the domain name
        buffer[offset++] = 0;

        // Write TYPE (2 bytes)
        buffer[offset++] = (rtype >> 8) & 0xFF;
        buffer[offset++] = rtype & 0xFF;

        // Write CLASS (2 bytes)
        buffer[offset++] = (rclass >> 8) & 0xFF;
        buffer[offset++] = rclass & 0xFF;

        // Write TTL (4 bytes)
        buffer[offset++] = (ttl >> 24) & 0xFF;
        buffer[offset++] = (ttl >> 16) & 0xFF;
        buffer[offset++] = (ttl >> 8) & 0xFF;
        buffer[offset++] = ttl & 0xFF;

        // Write RDLENGTH (2 bytes)
        buffer[offset++] = (rdlength >> 8) & 0xFF;
        buffer[offset++] = rdlength & 0xFF;

        // Write RDATA
        // For A records (IPv4 addresses), convert string representation to binary

        // Parse IP address string (e.g., "8.8.8.8") into 4 bytes
        int ipParts[4] = {0};
        int ipPartIndex = 0;
        for (char c : rdata)
        {
            if (c == '.')
            {
                ipPartIndex++;
            }
            else
            {
                ipParts[ipPartIndex] = ipParts[ipPartIndex] * 10 + (c - '0');
            }
        }

        // Write the 4 bytes of the IP address
        for (int i = 0; i < 4; i++)
        {
            buffer[offset++] = ipParts[i] & 0xFF;
        }

        return offset;
    }
};

class DNSStore
{
    std::unordered_map<std::string, ResourceRecord> records;

public:
    DNSStore()
    {
        addRecord("codecrafters.io", ResourceRecord("codecrafters.io", 1, 1, 1, 4, "8.8.8.8"));
    }

    void addRecord(const std::string &name, const ResourceRecord &record)
    {
        records[name] = record;
    }

    ResourceRecord getRecord(const std::string &name)
    {
        if (records.find(name) == records.end())
        {
            return ResourceRecord(name, 1, 1, 1, 4, "0.0.0.0");
        }
        return records[name];
    }
};
DNSStore dns_store;

struct Question
{
    std::string name;
    uint16_t qtype;
    uint16_t qclass;

    int serialize(char *buffer, int offset) const
    {
        // Write domain name in DNS format (length byte followed by characters)
        std::string name_copy = name;
        size_t pos = 0;
        size_t next;

        // Process each label (part between dots)
        while ((next = name_copy.find('.', pos)) != std::string::npos)
        {
            int labelLength = next - pos;
            buffer[offset++] = labelLength; // Label length

            // Copy the label characters
            for (int i = 0; i < labelLength; i++)
            {
                buffer[offset++] = name_copy[pos + i];
            }

            pos = next + 1; // Skip the dot
        }

        // Handle the last label (after the last dot or the entire name if no dots)
        int labelLength = name_copy.length() - pos;
        if (labelLength > 0)
        {
            buffer[offset++] = labelLength; // Label length

            // Copy the label characters
            for (int i = 0; i < labelLength; i++)
            {
                buffer[offset++] = name_copy[pos + i];
            }
        }

        // Add null byte to terminate the domain name
        buffer[offset++] = 0;

        // Write QTYPE (2 bytes)
        buffer[offset++] = (qtype >> 8) & 0xFF;
        buffer[offset++] = qtype & 0xFF;

        // Write QCLASS (2 bytes)
        buffer[offset++] = (qclass >> 8) & 0xFF;
        buffer[offset++] = qclass & 0xFF;

        return offset;
    }

    // Deserialize a question from a buffer, offset is updated in place
    static Question deserialize(const char *buffer, int &offset, int messageStart = 0)
    {
        Question q;

        // Parse domain name
        std::string name;
        int labelOffset = offset;
        bool compressedNameUsed = false;

        while (true)
        {
            uint8_t labelLength = (uint8_t)buffer[labelOffset++];
            // Check if this is a pointer (compression)
            if ((labelLength & 0xC0) == 0xC0)
            {
                // It's a pointer - the offset is the lower 14 bits of the 2-byte pointer
                if (!compressedNameUsed)
                {
                    // Only advance offset once - the first time we encounter a pointer
                    offset = labelOffset + 1; // Skip past the 2-byte pointer
                    compressedNameUsed = true;
                }

                // Calculate the pointer offset (lower 14 bits)
                uint16_t pointerOffset = ((labelLength & 0x3F) << 8) | (uint8_t)buffer[labelOffset];
                labelOffset = pointerOffset + messageStart;
                continue; // Go to the new position and continue parsing
            }
            // If length is 0, we've reached the end of the domain name
            if (labelLength == 0)
                break;

            // Add dot between labels (except for the first one)
            if (!name.empty())
                name += ".";

            // Copy the characters for this label
            for (int j = 0; j < labelLength; j++)
            {
                name += buffer[labelOffset++];
            }
        }
        if (!compressedNameUsed)
        {
            offset = labelOffset;
        }

        q.name = name;

        // Parse QTYPE (2 bytes)
        q.qtype = ((uint8_t)buffer[offset] << 8) | (uint8_t)buffer[offset + 1];
        offset += 2;

        // Parse QCLASS (2 bytes)
        q.qclass = ((uint8_t)buffer[offset] << 8) | (uint8_t)buffer[offset + 1];
        offset += 2;

        return q;
    }

    int size() const
    {
        // Domain name: length of labels + 1 byte per label length + 1 byte for null terminator
        int nameSize = name.length() + 2; // +2 for label length bytes and null terminator
        for (char c : name)
        {
            if (c == '.')
                nameSize++; // Each dot becomes a label length byte
        }
        // Add 4 bytes for QTYPE (2) and QCLASS (2)
        return nameSize + 4;
    }
};

class DNSMessage
{
public:
    uint16_t id;
    bool QR;
    uint8_t OPCODE;
    bool AA;
    bool TC;
    bool RD;
    bool RA;
    uint8_t Z;
    bool AD;
    bool CD;
    uint8_t RCODE;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;

    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;

    int size()
    {
        // Calculate buffer size: 12 bytes for header + space for questions
        int bufferSize = 12;
        for (const auto &question : questions)
        {
            bufferSize += question.size();
        }
        for (const auto &answer : answers)
        {
            bufferSize += answer.size();
        }

        return bufferSize;
    }

    char *serialize()
    {
        int bufferSize = this->size();
        char *buffer = new char[bufferSize];
        memset(buffer, 0, bufferSize);

        // Bytes 0-1: ID (16 bits)
        buffer[0] = (id >> 8) & 0xFF;
        buffer[1] = id & 0xFF;

        // Byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
        buffer[2] = (QR << 7) | ((OPCODE & 0x0F) << 3) | (AA << 2) | (TC << 1) | RD;

        // Byte 3: RA(1) | Z(3) | RCODE(4)
        buffer[3] = (RA << 7) | ((Z & 0x07) << 4) | (AD << 3) | (CD << 2) | (RCODE & 0x0F);

        // Bytes 4-5: QDCOUNT (16 bits)
        buffer[4] = (QDCOUNT >> 8) & 0xFF;
        buffer[5] = QDCOUNT & 0xFF;

        // Bytes 6-7: ANCOUNT (16 bits)
        buffer[6] = (ANCOUNT >> 8) & 0xFF;
        buffer[7] = ANCOUNT & 0xFF;

        // Bytes 8-9: NSCOUNT (16 bits)
        buffer[8] = (NSCOUNT >> 8) & 0xFF;
        buffer[9] = NSCOUNT & 0xFF;

        // Bytes 10-11: ARCOUNT (16 bits)
        buffer[10] = (ARCOUNT >> 8) & 0xFF;
        buffer[11] = ARCOUNT & 0xFF;

        // Write questions
        int offset = 12;
        for (const auto &question : questions)
        {
            offset = question.serialize(buffer, offset);
        }
        for (const auto &answer : answers)
        {
            offset = answer.serialize(buffer, offset);
        }

        return buffer;
    }

    static DNSMessage deserialize(const char *buffer)
    {
        DNSMessage msg;
        int messageStart = 0;

        // Bytes 0-1: ID (16 bits)
        msg.id = ((uint8_t)buffer[0] << 8) | (uint8_t)buffer[1];

        // Byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
        msg.QR = (buffer[2] >> 7) & 0x01;
        msg.OPCODE = (buffer[2] >> 3) & 0x0F;
        msg.AA = (buffer[2] >> 2) & 0x01;
        msg.TC = (buffer[2] >> 1) & 0x01;
        msg.RD = buffer[2] & 0x01;

        // Byte 3: RA(1) | Z(3) | RCODE(4)
        msg.RA = (buffer[3] >> 7) & 0x01;
        msg.Z = (buffer[3] >> 4) & 0x07;
        msg.AD = (buffer[3] >> 3) & 0x01;
        msg.CD = (buffer[3] >> 2) & 0x01;
        msg.RCODE = 0 ? 0 : 4;

        // Bytes 4-5: QDCOUNT (16 bits)
        msg.QDCOUNT = ((uint8_t)buffer[4] << 8) | (uint8_t)buffer[5];

        // Bytes 6-7: ANCOUNT (16 bits)
        msg.ANCOUNT = ((uint8_t)buffer[6] << 8) | (uint8_t)buffer[7];

        // Bytes 8-9: NSCOUNT (16 bits)
        msg.NSCOUNT = ((uint8_t)buffer[8] << 8) | (uint8_t)buffer[9];

        // Bytes 10-11: ARCOUNT (16 bits)
        msg.ARCOUNT = ((uint8_t)buffer[10] << 8) | (uint8_t)buffer[11];

        int offset = 12;
        for (int i = 0; i < msg.QDCOUNT; i++)
        {
            msg.questions.push_back(Question::deserialize(buffer, offset, messageStart));
        }

        return msg;
    }

    void resolve()
    {
        for (const auto &question : questions)
        {
            answers.push_back(dns_store.getRecord(question.name));
        }
    }

    std::vector<Question> serializeQuestions()
    {
        std::vector<Question> serializedQuestions;
        for (const auto &question : questions)
        {
            serializedQuestions.push_back(question);
        }
        return serializedQuestions;
    }
    void debug_print()
    {
        DEBUG("DNS Message of size " << this->size() << ":");
        DEBUG("  ID: " << id);
        DEBUG("  QR: " << (QR ? "1" : "0"));
        DEBUG("  OPCODE: " << (int)OPCODE);
        DEBUG("  AA: " << (AA ? "1" : "0"));
        DEBUG("  TC: " << (TC ? "1" : "0"));
        DEBUG("  RD: " << (RD ? "1" : "0"));
        DEBUG("  RA: " << (RA ? "1" : "0"));
        DEBUG("  Z: " << (int)Z);
        DEBUG("  AD: " << (AD ? "1" : "0"));
        DEBUG("  CD: " << (CD ? "1" : "0"));
        DEBUG("  RCODE: " << (int)RCODE);
        DEBUG("  QDCOUNT: " << QDCOUNT);
        DEBUG("  ANCOUNT: " << ANCOUNT);
        DEBUG("  NSCOUNT: " << NSCOUNT);
        DEBUG("  ARCOUNT: " << ARCOUNT);
        DEBUG("  Questions: ");
        for (const auto &question : questions)
        {
            DEBUG("    Name: " << question.name);
            DEBUG("    Type: " << question.qtype);
            DEBUG("    Class: " << question.qclass);
        }
        DEBUG("  Answers: ");
        for (const auto &answer : answers)
        {
            DEBUG("    Name: " << answer.name);
            DEBUG("    IP: " << answer.rdata);
        }
    }
};

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

    // Parse command line arguments for resolver address
    std::string resolverIp = "8.8.8.8"; // Default to Google DNS
    int resolverPort = 53;              // Default DNS port

    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "--resolver" && i + 1 < argc)
        {
            std::string resolver = argv[i + 1];
            size_t colonPos = resolver.find(':');

            if (colonPos != std::string::npos)
            {
                resolverIp = resolver.substr(0, colonPos);
                std::string portStr = resolver.substr(colonPos + 1);
                try
                {
                    resolverPort = std::stoi(portStr);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Invalid port number: " << portStr << std::endl;
                    return 1;
                }
            }
            else
            {
                std::cerr << "Invalid resolver format. Expected <ip>:<port>" << std::endl;
                return 1;
            }

            i++; // Skip the next argument since we've processed it
        }
    }

    std::cout << "Using DNS resolver: " << resolverIp << ":" << resolverPort << std::endl;

    // Uncomment this block to pass the first stage
    int udpSocket;
    struct sockaddr_in clientAddress;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }

    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(2053),
        .sin_addr = {htonl(INADDR_ANY)},
    };

    if (bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    // Create a socket for forwarding queries to upstream DNS server
    int forwardSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (forwardSocket == -1)
    {
        std::cerr << "Forward socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }
    // Configure the forwarding DNS server address
    struct sockaddr_in dnsServerAddr;
    dnsServerAddr.sin_family = AF_INET;
    dnsServerAddr.sin_port = htons(resolverPort);
    if (inet_pton(AF_INET, resolverIp.c_str(), &dnsServerAddr.sin_addr) <= 0)
    {
        std::cerr << "Invalid resolver IP address: " << resolverIp << std::endl;
        return 1;
    }

    int bytesRead;
    char buffer[1024];
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true)
    {
        // Receive data
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                            reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1)
        {
            perror("Error receiving data");
            break;
        }

        DEBUG("Received " << bytesRead << " bytes containing:  " << buffer);

        // Parse incoming DNS message
        DNSMessage incomingMsg = DNSMessage::deserialize(buffer);
        incomingMsg.debug_print();
        incomingMsg.QR = true;

        incomingMsg.resolve();

        char *response = incomingMsg.serialize();

        if (sendto(forwardSocket, response, incomingMsg.size(), 0,
                    reinterpret_cast<struct sockaddr *>(&dnsServerAddr), sizeof(dnsServerAddr)) == -1)
        {
            perror("Failed to send response");
        }


        // Free allocated memory
        delete[] response;
    }

    close(udpSocket);

    return 0;
}
