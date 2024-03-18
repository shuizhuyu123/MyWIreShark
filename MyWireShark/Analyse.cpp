#include "Analyse.h"

Analyse::Analyse(QByteArray&& byte, int cplen, MyWireShark* window)
	:array(byte),cplen(cplen),window(window)
{
	
}
void Analyse::run() {
	unpack(array.constData());
}
void Analyse::unpack(const char* packet) {
	ether_header* eth = (ether_header*)packet;
	QStringList list;
	QString src = "%1:%2:%3:%4:%5:%6";
	QString dst = "%1:%2:%3:%4:%5:%6";
	for (int i = 0; i < 6; i++) {
		src = src.arg(QString::number(eth->ether_shost[i], 16));
		dst = dst.arg(QString::number(eth->ether_dhost[i], 16));
	}

	root = QStringList() << "Ethernet " << "src:" + src << "dst:" + dst;
	ProtocolItem item(root);
	
	item.children.append(ProtocolItem(QStringList() << "Source:" << src));

	item.children.append(QStringList() << "Destination:" << dst);

	item.children.append(QStringList() << "Type:" << "0x" + QString::number(ntohs(eth->ether_type), 16).rightJustified(4, '0'));

	content.items.append(std::move(item));

	
	switch (ntohs(eth->ether_type)) {
	case 0x0800: {
		unpackIP(packet+14);
		break;
	}
	default:
		summary<<src<<dst<< "None";
	}
	summary << QString::number(cplen);
	content.content = std::move(array);
	QMetaObject::invokeMethod(window, "setitem", Qt::AutoConnection, Q_ARG(QStringList, summary), Q_ARG(ProtocolData, content));
}
void Analyse::unpackIP(const char* packet)
{
	char src[32], dst[32];
	iphead* ipheader = (iphead*)packet;
	children.clear();
	
	if (inet_ntop(AF_INET, &ipheader->m_ulSrcIP, src, sizeof(src)) && inet_ntop(AF_INET, &ipheader->m_ulDestIP, dst, sizeof(dst))) {
		
		ProtocolItem item(QStringList() << "Internet Protocal version " + QString::number(ipheader->version) << "Src:" + QString(src) << "Dst" + QString(dst));
	
		item.children.append(QStringList() << "Version:" << QString::number(ipheader->version, 2).rightJustified(4, '0') + "...." << QString::number(ipheader->version));

		item.children.append(QStringList() << "Header length:" << "...." + QString::number(ipheader->m_HDlen, 2).rightJustified(4, '0') << QString::number(ipheader->m_HDlen * 4));

		item.children.append(QStringList() << "Tos:" << QString::number(ipheader->m_byTOS, 2).rightJustified(8, '0'));

		item.children.append(QStringList() << "Total length:" << QString::number(ntohs(ipheader->m_byTotalLen)));

		unsigned short flag = (ntohs(ipheader->m_usFlagFragOffset) >> 13) & 0x7;
		item.children.append(QStringList() << "Flag:" << QString::number(flag, 2).rightJustified(3, '0') + ". ....");

		unsigned short fragOffset = ntohs(ipheader->m_usFlagFragOffset) & 0x1FFF;
		item.children.append(QStringList() << "Fragment Offset:" << "... " + QString::number(fragOffset, 2).rightJustified(13, '0'));

		item.children.append(QStringList() << "TTL:" << QString::number(ipheader->m_byTTL));

		item.children.append(QStringList() << "Protocol:" << QString::number(ipheader->byProtocol));

		item.children.append(QStringList() << "Checksum:" << "0x" + QString::number(ntohs(ipheader->m_usHChecksum), 16).rightJustified(4, '0'));

		item.children.append(QStringList() << "Source Address:" << src);

		item.children.append(QStringList() << "Destination Address" << dst);

		content.items.append(std::move(item));

		summary << src << dst;
		switch (ipheader->byProtocol){
			case 1: {
				summary << "ICMP";
				unpackICMP(packet  + ipheader->m_HDlen * 4, ipheader->m_HDlen * 4);
				break;
			}
			case 2: {
				summary << "IGMP";
				break;
			}
			case 6: {
				unpackTCP(packet  + ipheader->m_HDlen * 4, ipheader->m_HDlen * 4);
				break;
			}
			case 17: {
				unpackUDP(packet  + ipheader->m_HDlen * 4, ipheader->m_HDlen * 4);
				break;
			}
			case 89: {
				summary << "OSPF";
				break;
			}
			default: {
				summary << "NONE";
				break;
			}
		}
		
	}
}
void Analyse::unpackTCP(const char* packet,int len)
{
	tcp_header* tcp = (tcp_header*)packet;
	unsigned short srcport = ntohs(tcp->SourPort);
	unsigned short dstport = ntohs(tcp->DestPort);

	children.clear();

	ProtocolItem item(QStringList() << "Transmission Control Protocol " << "Src port:" + QString::number(srcport) << "Dst port:" + QString::number(dstport));
	
	item.children.append(QStringList() << "Source Port:" << QString::number(srcport));

	item.children.append(QStringList() << "Dst Port:" << QString::number(dstport));

	item.children.append(QStringList() << "Sequence Number" << QString::number(ntohl(tcp->SequNum)));

	item.children.append(QStringList() << "Ackonwledge Number" << QString::number(ntohl(tcp->AcknowledgeNum)));

	item.children.append(QStringList() << "Window Size" << QString::number(ntohs(tcp->WindowSize)));

	unsigned char flags = tcp->flags;
	QStringList flag;
	if (flags & 0x10) {
		flag += "ACK ";
	}
	if (flags & 0x08) {
		flag += "PSH ";
	}
	if (flags & 0x01) {
		flag += "FIN ";
	}
	if (flags & 0x04) {
		flag += "RST ";
	}

	item.children.append(QStringList() << "Flags:" << "0x" + QString::number(flags, 16).rightJustified(3, '0') << flag.join(" "));

	item.children.append(QStringList() << "Checksum" << "0x" + QString::number(ntohs(tcp->CheckSum), 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "Urgent Pointer" << QString::number(ntohs(tcp->surgentPointer)));

	content.items.append(std::move(item));
	
	if ( dstport == 25 || srcport == 25) {
		unpackSMTP(packet + tcp->offset * 4, cplen - 14 - len - tcp->offset * 4);
	}
	else if (dstport == 80||srcport==80) {
		if (kmpSearch(packet + tcp->offset * 4, cplen - 14 - len - tcp->offset* 4, "HTTP", 4)) {
			unpackHttp(packet + tcp->offset * 4, cplen - 14 - len - tcp->offset * 4);
		}
		else {

			children.clear();

			ProtocolItem item(QStringList() << "Hypertext Transfer Protocol");

			item.children.append(QStringList() << "data" << QString::fromUtf8(packet + tcp->offset * 4, cplen - 14 - len - tcp->offset * 4));

			content.items.append(std::move(item));
			summary << "TCP";
		}
	}
	else
		summary << "TCP";
}
void Analyse::unpackUDP(const char* packet, int len)
{
	udp_header* udp = (udp_header*)(packet);
	unsigned short srcport = ntohs(udp->sport);
	unsigned short dstport = ntohs(udp->dport);
	children.clear();

	ProtocolItem item(QStringList() << "User Datagram Protocol" << "Src Port:" + QString::number(srcport) << "Dst Port:" + QString::number(dstport));
	
	item.children.append(QStringList() << "Source Port:" << QString::number(srcport));

	item.children.append(QStringList() << "Dst Port:" << QString::number(dstport));

	item.children.append(QStringList() << "Length:" << "0x" + QString::number(ntohs(udp->datalen)));

	item.children.append(QStringList() << "Checksum:" << "0x" + QString::number(ntohs(udp->checksum), 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "Data" << QString::fromUtf8(QByteArray(packet + sizeof(udp_header), array.size() - 14 - len - sizeof(udp_header)).toHex()));
	
	content.items.append(item);
	
	if (dstport == 53||srcport==53){
		unpackDNS(packet + 8, cplen - 14 - len - 8);
	}
	else if (dstport == 1900 || srcport == 1900) {
		unpackSSDP(packet + 8, cplen - 14 - len - 8);
	}
	else
		summary << "UDP";
}
void Analyse::unpackICMP(const char* packet, int len)
{
	icmphead* icmp = (icmphead*)(packet);
	children.clear();

	ProtocolItem item(QStringList() << "Internet Control Message Protocol");

	item.children.append(QStringList() << "Type" << QString::number(icmp->m_byType));

	item.children.append(QStringList() << "Code" << QString::number(icmp->m_byCode));

	item.children.append(QStringList() << "Checksum" << "0x" + QString::number(ntohs(icmp->m_usChecksum), 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "Identifier(BE)" << QString::number(icmp->m_usID) << "0x" + QString::number(icmp->m_usID, 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "Identifier(LE)" << QString::number(ntohs(icmp->m_usID)) << "0x" + QString::number(ntohs(icmp->m_usID), 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "SeqNumber(BE)" << QString::number(icmp->m_usSeq) << "0x" + QString::number(icmp->m_usSeq, 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "SeqNumber(LE)" << QString::number(ntohs(icmp->m_usSeq)) << "0x" + QString::number(ntohs(icmp->m_usSeq), 16).rightJustified(4, '0'));

	item.children.append(QStringList() << "Data" << QString::fromUtf8(QByteArray(packet + sizeof(icmphead), array.size() - (14 + len + sizeof(icmphead))).toHex()));

	content.items.append(std::move(item));
}
void Analyse::unpackHttp(const char* packet, int len)
{
	summary << "HTTP";
	children.clear();

	ProtocolItem item(QStringList() << "Hypertext Transfer Protocol");

	QStringList list;
	QString line;
	for (int i = 0; i < len; i++) {
		if (packet[i] == '\r' && i + 1 < len && packet[i + 1] == '\n') {
			if (!line.isEmpty()) {
				item.children.append(QStringList()<<line);
				line.clear();
			 }
			i++; 
		}
		else {
		line += packet[i];
		}
	}
	if (!line.isEmpty())

	item.children.append(QStringList()<<line);
	content.items.append(std::move(item));
}
void Analyse::unpackDNS(const char* packet, int len)
{
	summary << "DNS";
	const dnshead* dns = reinterpret_cast<dnshead*>(const_cast<char*>(packet));
	children.clear();

	unsigned short Flag = ntohs(dns->Flag);
	int flag = (Flag & 0x8000) >> 15;

	ProtocolItem item(QStringList() << "Domain Name System(" + QString(flag == 0 ? "query)" : "response)"));

	item.children.append(QStringList() << "Transaction ID" << "0x" + QString::number(dns->TransactionID, 16).rightJustified(4, '0'));

	ProtocolItem subitem(QStringList() << "Flag" << "0x" + QString::number(Flag, 16).rightJustified(4, '0')+QString(" "+flag ? "response" : "query"));

	subitem.children.append(QStringList() << QString::number(flag) + "..............." << "flag: "+QString(flag ? "response" : "query"));

	int OpCode = (Flag & 0x7800) >> 11;
	subitem.children.append(QStringList() << "." + QString::number(OpCode, 16).rightJustified(4, '0') + "..........." << "OpCode: "+QString((OpCode == 0 ? "Standard Query" : (OpCode == 1 ? "Inverse Query" : (OpCode == 2 ? "Server Status Request" : "Reserved"))) + QString("(" + QString::number(OpCode) + ")")));

	int aaFlag = (Flag & 0x0400) >> 10;
	subitem.children.append(QStringList() << "....." + QString::number(aaFlag) + ".........." << "Authoritative Answer (AA) Flag "+QString(aaFlag ? "Authority" : "Not Authority"));

	int tcFlag = (Flag & 0x0200) >> 9;
	subitem.children.append(QStringList() << "......" + QString::number(tcFlag) + "........." << "Truncation (TC) Flag "+QString(tcFlag ? "Set" : "Not set"));

	int rdFlag = (Flag & 0x0100) >> 8;
	subitem.children.append(QStringList() << "......." + QString::number(rdFlag) + "........" << "Recursion Desired (RD) Flag "+QString(rdFlag ? "Set" : "Not set"));

	int raFlag = (Flag & 0x0080) >> 7;
	subitem.children.append(QStringList() << "........" + QString::number(raFlag) + "......." << "Recursion Available (RA) Flag "+QString(raFlag ? "Available" : "Not Available"));

	int rcode = (Flag & 0x10);
	subitem.children.append(QStringList() << "............" + QString::number(rcode, 16).rightJustified(4, '0') << "Reply Code "+QString(!rcode ? "no error" : "error"));

	item.children.append(std::move(subitem));

	item.children.append(QStringList() << "Questions:" << QString::number(ntohs(dns->QUestions)));

	item.children.append(QStringList() << "Answer RRs" << QString::number(ntohs(dns->Answer_RRS)));

	item.children.append(QStringList() << "Authority RRs" << QString::number(ntohs(dns->Authority_RRS)));

	item.children.append(QStringList() << "Additional RRs" << QString::number(ntohs(dns->Additonal_RRS)));

	ProtocolItem Query(QStringList() << "Queries");

	std::string domainName;
	int i = 0;
	const char* data = packet + sizeof(dnshead);
	for (int i = 0; i < ntohs(dns->QUestions); i++) {
		while (*data != 0) {
			
			if ((*data + *(data + 1)) != 0xc00c) {
				while (*data != 0) {
					int labelLength = *data;
					if ((labelLength & 0xC0) == 0xC0) {
						break;
					}
					else {
						domainName.append(data + 1, labelLength);
						data += labelLength + 1;
						if (*data != 0) {
							domainName += ".";
						}
					}
				}
			}
		}
		unsigned short queryType = ntohs(*reinterpret_cast<const unsigned short*>(data + 1));
		unsigned short queryClass = ntohs(*reinterpret_cast<const unsigned short*>(data + 3));
		data += 5;
		QString Type;
		switch (queryType) {
		case 1:
			Type = "A";
			break;
		case 2:
			Type = "NS";
			break;
		case 5:
			Type = "CNAME";
			break;
		case 12:
			Type = "PTR";
			break;
		case 15:
			Type = "MX";
			break;
		case 28:
			Type = "AAAA";
			break;
		default:
			Type = "Unknown";
			break;
		}

		Query.children.append(QStringList() << QString::fromStdString(domainName) << "Type: " + Type +",Class: 0x" + QString::number(queryClass, 16).rightJustified(4, '0'));
	}

	item.children.append(std::move(Query));

	ProtocolItem Answer(QStringList() << "Answer");

	for (int i = 0; i < ntohs(dns->Answer_RRS); i++) {
		while (*data != 0) {
			int labelLength = *data;
			if ((labelLength & 0xC0) == 0xC0) {
					// 如果遇到压缩标签，跳过
					break;
			}
			else {
				domainName.append(data + 1, labelLength);
				data += labelLength + 1;
				if (*data != 0) {
						domainName += ".";
				}
			}
		}
			data += 1;
		// 解析类型、类别和数据长度
		unsigned short answerType = ntohs(*reinterpret_cast<const unsigned short*>(data + 1));
		unsigned short answerClass = ntohs(*reinterpret_cast<const unsigned short*>(data + 3));
		unsigned short dataLength = ntohs(*reinterpret_cast<const unsigned short*>(data + 9));
		data += 11;

		QString answerTypeString;
		switch (answerType) {
		case 1:
			answerTypeString = "A";
			break;
		case 2:
			answerTypeString = "NS";
			break;
		case 5:
			answerTypeString = "CNAME";
			break;
		case 12:
			answerTypeString = "PTR";
			break;
		case 15:
			answerTypeString = "MX";
			break;
		case 28:
			answerTypeString = "AAAA";
			break;
		default:
			answerTypeString = "Unknown";
			break;
		}
		// 解析数据部分
		QString answerData;
		if (answerType == 1) {
			// A 类型记录，解析 IPv4 地址
			QString ipAddress;
			for (int j = 0; j < dataLength; j++) {
				ipAddress += QString::number(static_cast<unsigned char>(*(data + j)));
				if (j < dataLength - 1) {
					ipAddress += ".";
				}
			}
			answerData = ipAddress;
		}
		else if (answerType == 2) {
			// NS 类型记录，解析主机名
			std::string nsRecord;
			while (*data != 0) {
				int labelLength = *data;
				if ((labelLength & 0xC0) == 0xC0) {
					// 如果遇到压缩标签，跳过
					break;
				}
				else {
					nsRecord.append(data + 1, labelLength);
					data += labelLength + 1;
					if (*data != 0) {
						nsRecord += ".";
					}
				}
			}
			answerData = QString::fromStdString(nsRecord);
		}
		else if (answerType == 5) {
			// CNAME 类型记录，解析别名
			std::string cnameRecord;
			while (*data != 0) {
				int labelLength = *data;
				if ((labelLength & 0xC0) == 0xC0) {
					// 如果遇到压缩标签，跳过
					break;
				}
				else {
					cnameRecord.append(data + 1, labelLength);
					data += labelLength + 1;
					if (*data != 0) {
						cnameRecord += ".";
					}
				}
			}
			answerData = QString::fromStdString(cnameRecord);
		}
		else {
			// 其他类型记录，直接跳过数据部分
			data += dataLength;
			answerData = "Unknown";
		}
		Answer.children.append(QStringList() << QString::fromStdString(domainName) << "Type: " + answerTypeString +",addr: " + answerData);
	}

	if(dns->Answer_RRS)
	item.children.append(std::move(Answer));

	content.items.append(std::move(item));
}
void Analyse::unpackSMTP(const char* packet, int len)
{
	summary << "SMTP";

	ProtocolItem item(QStringList() << "Simple Mail Transfer Protocol");

	QString line;
	for (int i = 0; i < len; i++) {
		if (packet[i] == '\r' && i + 1 < len && packet[i + 1] == '\n') {
			if (!line.isEmpty()) {
				item.children.append(QStringList()<<line);
				line.clear();
			}
			i++;
		}
		else {
			line += packet[i];
		}
	}
	if (!line.isEmpty())
		item.children.append(QStringList() << line);

	content.items.append(std::move(item));

}
void Analyse::unpackSSDP(const char* packet, int len)
{
	summary << "SSDP";
	ProtocolItem item(QStringList() << "Simple Service Discovery Protocol");

	QString line;
	for (int i = 0; i < len; i++) {
		if (packet[i] == '\r' && i + 1 < len && packet[i + 1] == '\n') {
			if (!line.isEmpty()) {
				item.children.append(QStringList() << line);
				line.clear();
			}
			i++;
		}
		else {
			line += packet[i];
		}
	}
	if (!line.isEmpty())
		item.children.append(QStringList() << line);

	content.items.append(std::move(item));
}
void Analyse::getNextArray(const char* pattern, int* next, int len) {
	int i = 0, j = -1;
	next[0] = -1;

	while (i < len) {
		if (j == -1 || pattern[i] == pattern[j]) {
			i++;
			j++;
			next[i] = j;
		}
		else {
			j = next[j];
		}
	}
}

bool Analyse::kmpSearch(const char* text, int textLen, const char* pattern, int patternLen) {
	std::vector<int> next(patternLen + 1);
	getNextArray(pattern, next.data(), patternLen);

	int i = 0, j = 0;
	while (i < textLen && j < patternLen) {
		if (j == -1 || text[i] == pattern[j]) {
			i++;
			j++;
		}
		else {
			j = next[j];
		}
	}
	if (j == patternLen) {
		return true;  
	}

	return false; 
}
Analyse::~Analyse()
{
	array.clear();
}
