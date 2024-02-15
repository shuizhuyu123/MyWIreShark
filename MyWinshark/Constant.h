#pragma once
typedef struct ether_header
{
    unsigned char ether_dhost[6];    // 目标地址
    unsigned char ether_shost[6];    // 源地址
    unsigned short ether_type;       // 以太网类型
} ether_header;
typedef struct arphdr
{
    unsigned short ar_hrd;
    unsigned short ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short ar_op;
}ARP_HEADER;
typedef struct IPHeader
{
	unsigned char m_HDlen : 4;                 // 4位首部长度
	unsigned char version : 4;                 // 4位版本号
	unsigned char m_byTOS;			        // 8服务类型
	unsigned short m_byTotalLen;	        // 16总长度
	unsigned short m_usID;			        // 16标识
	unsigned short m_usFlagFragOffset;		// 3位标识+13位片偏移
	unsigned char m_byTTL;					// 8TTL
    unsigned char byProtocol;				// 8位协议
	unsigned short m_usHChecksum;			// 16位首部检验和
	unsigned int m_ulSrcIP;				    // 32源IP地址
	unsigned int m_ulDestIP;				// 32目的IP地址
}iphead;
typedef struct tcp_header
{
    unsigned short SourPort;                 // 源端口号16bit
    unsigned short DestPort;                 // 目的端口号16bit
    unsigned int SequNum;           // 序列号32bit
    unsigned int AcknowledgeNum;    // 确认号32bit
    unsigned char reserved : 4, offset : 4; // 预留偏移
    unsigned char  flags;               // 标志 
    unsigned short WindowSize;               // 窗口大小16bit
    unsigned short CheckSum;                 // 检验和16bit
    unsigned short surgentPointer;           // 紧急数据偏移量16bit
}tcp_header;
typedef struct udp_header
{
    unsigned short sport;   // 源端口
    unsigned short dport;   // 目标端口
    unsigned short datalen; // UDP数据长度
    unsigned short checksum;//校验和
}udp_header;
typedef struct ICMPHeader
{
    BYTE m_byType;					// 类型
    BYTE m_byCode;					// 代码
    unsigned short m_usChecksum;			// 检验和
    unsigned short m_usID;					// 标识符
    unsigned short m_usSeq;					// 序号
}icmphead;
