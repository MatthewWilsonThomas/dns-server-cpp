#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <vector>
#include <string>

#define DEBUG_OUTPUT 0

#define DEBUG(x)      \
    if (DEBUG_OUTPUT) \
        std::cout << x << std::endl;

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

    struct Question {
        std::string name;
        uint16_t qtype;
        uint16_t qclass;
    };

    std::vector<Question> questions;

    int responseSize() {
        // Calculate buffer size: 12 bytes for header + space for questions
        int bufferSize = 12;
        for (const auto &question : questions) {
            // Domain name: 1 byte per label length + label characters + 1 byte for null terminator
            bufferSize += question.name.length() + 2; // +2 for the length bytes and terminator
            // Add 4 bytes for QTYPE (2) and QCLASS (2)
            bufferSize += 4;
        }
        
        return bufferSize;
    }

    char *serialize()
    {
        int bufferSize = responseSize();
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
        for (const auto &question : questions) {
            // Write domain name in DNS format (length byte followed by characters)
            std::string name = question.name;
            size_t pos = 0;
            size_t next;
            
            // Process each label (part between dots)
            while ((next = name.find('.', pos)) != std::string::npos) {
                int labelLength = next - pos;
                buffer[offset++] = labelLength; // Label length
                
                // Copy the label characters
                for (int i = 0; i < labelLength; i++) {
                    buffer[offset++] = name[pos + i];
                }
                
                pos = next + 1; // Skip the dot
            }
            
            // Handle the last label (after the last dot or the entire name if no dots)
            int labelLength = name.length() - pos;
            if (labelLength > 0) {
                buffer[offset++] = labelLength; // Label length
                
                // Copy the label characters
                for (int i = 0; i < labelLength; i++) {
                    buffer[offset++] = name[pos + i];
                }
            }
            
            // Add null byte to terminate the domain name
            buffer[offset++] = 0;
            
            // Write QTYPE (2 bytes)
            buffer[offset++] = (question.qtype >> 8) & 0xFF;
            buffer[offset++] = question.qtype & 0xFF;
            
            // Write QCLASS (2 bytes)
            buffer[offset++] = (question.qclass >> 8) & 0xFF;
            buffer[offset++] = question.qclass & 0xFF;
        }
        
        return buffer;
    }
    void parseQuestions(const char *buffer, int &offset)
    {        
        for (int i = 0; i < QDCOUNT; i++) {
            Question q;
            
            // Parse domain name
            std::string name;
            int startOffset = offset;
            
            while (true) {
                uint8_t labelLength = (uint8_t)buffer[offset++];
                
                // If length is 0, we've reached the end of the domain name
                if (labelLength == 0)
                    break;
                    
                // Add dot between labels (except for the first one)
                if (!name.empty())
                    name += ".";
                    
                // Copy the characters for this label
                for (int j = 0; j < labelLength; j++) {
                    name += buffer[offset++];
                }
            }
            
            q.name = name;
            
            // Parse QTYPE (2 bytes)
            q.qtype = ((uint8_t)buffer[offset] << 8) | (uint8_t)buffer[offset + 1];
            offset += 2;
            
            // Parse QCLASS (2 bytes)
            q.qclass = ((uint8_t)buffer[offset] << 8) | (uint8_t)buffer[offset + 1];
            offset += 2;
            
            this->questions.push_back(q);
            DEBUG("Parsed question: " << q.name << " (type=" << q.qtype << ", class=" << q.qclass << ")");
        }
    }

    static DNSMessage deserialize(const char *buffer)
    {
        DNSMessage msg;

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
        msg.RCODE = buffer[3] & 0x0F;

        // Bytes 4-5: QDCOUNT (16 bits)
        msg.QDCOUNT = ((uint8_t)buffer[4] << 8) | (uint8_t)buffer[5];

        // Bytes 6-7: ANCOUNT (16 bits)
        msg.ANCOUNT = ((uint8_t)buffer[6] << 8) | (uint8_t)buffer[7];

        // Bytes 8-9: NSCOUNT (16 bits)
        msg.NSCOUNT = ((uint8_t)buffer[8] << 8) | (uint8_t)buffer[9];

        // Bytes 10-11: ARCOUNT (16 bits)
        msg.ARCOUNT = ((uint8_t)buffer[10] << 8) | (uint8_t)buffer[11];

        int offset = 12;
        msg.parseQuestions(buffer, offset);

        return msg;
    }

    void debug_print()
    {
        DEBUG("DNS Message of size " << responseSize() << ":");
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
        for (const auto &question : questions) {
            DEBUG("    Name: " << question.name);
            DEBUG("    Type: " << question.qtype);
            DEBUG("    Class: " << question.qclass);
        }
    }
};

int main()
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

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

    int bytesRead;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true)
    {
        // Receive data
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1)
        {
            perror("Error receiving data");
            break;
        }

        DEBUG("Received " << bytesRead << " bytes containing:  " << buffer);

        // Parse incoming DNS message
        DNSMessage incomingMsg = DNSMessage::deserialize(buffer);
        incomingMsg.debug_print();

        incomingMsg.id = 1234;
        incomingMsg.QR = true;

        char *response = incomingMsg.serialize();

        if (sendto(udpSocket, response, incomingMsg.responseSize(), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1)
        {
            perror("Failed to send response");
        }

        // Free allocated memory
        delete[] response;
    }

    close(udpSocket);

    return 0;
}
