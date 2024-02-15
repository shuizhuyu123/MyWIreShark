#pragma once
typedef struct ether_header
{
    unsigned char ether_dhost[6];    // Ŀ���ַ
    unsigned char ether_shost[6];    // Դ��ַ
    unsigned short ether_type;       // ��̫������
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
	unsigned char m_HDlen : 4;                 // 4λ�ײ�����
	unsigned char version : 4;                 // 4λ�汾��
	unsigned char m_byTOS;			        // 8��������
	unsigned short m_byTotalLen;	        // 16�ܳ���
	unsigned short m_usID;			        // 16��ʶ
	unsigned short m_usFlagFragOffset;		// 3λ��ʶ+13λƬƫ��
	unsigned char m_byTTL;					// 8TTL
    unsigned char byProtocol;				// 8λЭ��
	unsigned short m_usHChecksum;			// 16λ�ײ������
	unsigned int m_ulSrcIP;				    // 32ԴIP��ַ
	unsigned int m_ulDestIP;				// 32Ŀ��IP��ַ
}iphead;
typedef struct tcp_header
{
    unsigned short SourPort;                 // Դ�˿ں�16bit
    unsigned short DestPort;                 // Ŀ�Ķ˿ں�16bit
    unsigned int SequNum;           // ���к�32bit
    unsigned int AcknowledgeNum;    // ȷ�Ϻ�32bit
    unsigned char reserved : 4, offset : 4; // Ԥ��ƫ��
    unsigned char  flags;               // ��־ 
    unsigned short WindowSize;               // ���ڴ�С16bit
    unsigned short CheckSum;                 // �����16bit
    unsigned short surgentPointer;           // ��������ƫ����16bit
}tcp_header;
typedef struct udp_header
{
    unsigned short sport;   // Դ�˿�
    unsigned short dport;   // Ŀ��˿�
    unsigned short datalen; // UDP���ݳ���
    unsigned short checksum;//У���
}udp_header;
typedef struct ICMPHeader
{
    BYTE m_byType;					// ����
    BYTE m_byCode;					// ����
    unsigned short m_usChecksum;			// �����
    unsigned short m_usID;					// ��ʶ��
    unsigned short m_usSeq;					// ���
}icmphead;
