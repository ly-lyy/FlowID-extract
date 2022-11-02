#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <iostream>
using namespace std;

/*   ------------------流标识提取程序-----------------------   */
/*   ------------------by  611-----------------------   */



//本程序针对CAIDA的pcap文件，并且只提取出pcap文件中，IP协议版本为IPv4，IP首部为20个字节，且传输协议为UDP或TCP的
//程序里设置了大量的回显信息，如果觉得浪费时间，可以删掉回显信息


#define WireShark_Total_PacketNums  158823  //运行本程序之前，先用Wireshark查看数据包总量，进行赋值

//pacp文件头结构体，24B
struct pcap_file_header
{
    unsigned int magic;       //Magic字段，4B
    unsigned short version_major;   //Major字段，2B
    unsigned short version_minor;   //Minor字段，2B
    unsigned int thiszone;      //Thiszone字段，4B
    unsigned int sigfigs;     //sigFigs字段，4B
    unsigned int snaplen;     //SnapLen字段，4B
    unsigned int linktype;    //Linktype字段，4B
};

//时间戳
struct time_val
{
    int tv_sec;     //时间戳高位,4B
    int tv_usec;    //时间戳低位,4B
};

//pcap数据包头结构体，16B
struct pcap_pkthdr
{
    struct time_val ts;  //时间戳（高+低），4B+4B
    unsigned int caplen;  //Caplen字段，4B
    unsigned int len;    //Len,4B
};


typedef struct FramHeader_t      //数据帧头 （以太网帧头）  14B
{ //Pcap捕获的数据帧头
    unsigned char DstMAC[6]; //目的MAC地址,6B
    unsigned char SrcMAC[6]; //源MAC地址,6B
    unsigned short FrameType;    //帧类型，2B
} FramHeader_t;


typedef struct IPHeader_t             //IP数据报头（共20B）
{
    unsigned char Ver_HLen;           //版本+报头长度 ，1B
    unsigned char TOS;                //服务类型，1B
    unsigned short TotalLen;            //总长度，2B
    unsigned short ID;                  //标识 ，2B
    unsigned short Flag_Segment;        //标志+片偏移，2B
    unsigned char TTL;                //生存周期，1B
    unsigned char Protocol;           //协议类型，1B
    unsigned short Checksum;            //头部校验和，2B
    unsigned int SrcIP;              //源IP地址（要用），4B
    unsigned int DstIP;              //目的IP地址（要用）,4B
} IPHeader_t;


typedef struct TCPHeader_t            //TCP数据报头,20B
{
    unsigned short SrcPort;           //源端口,2B
    unsigned short DstPort;           //目的端口,2B
    unsigned int SeqNO;               //序号,4B
    unsigned int AckNO;               //确认号,4B
    unsigned char HeaderLen;          //数据报头的长度(4 bit) + 保留(4 bit)  1B
    unsigned char Flags;              //标识TCP不同的控制消息,1B
    unsigned short Window;            //窗口大小,2B
    unsigned short Checksum;          //校验和,2B
    unsigned short UrgentPointer;     //紧急指针,2B

                                      //缺了个32位的选项，不知道加不加,4B
}TCPHeader_t;


typedef struct UDPHeader_s              //UDP数据包头,8B
{
    unsigned short SrcPort;                // 源端口号16bit,2B
    unsigned short DstPort;                // 目的端口号16bit,2B
    unsigned short len;                    // 数据包长度16bit,2B
    unsigned short checkSum;               // 校验和16bit,2B
}UDPHeader_t;

typedef struct Quintet  //五元组
{
	unsigned long SrcIP; //源IP地址 4B
	unsigned long DstIP; //目的IP地址,4B
    unsigned short SrcPort;     // 源端口号,2B
    unsigned short DstPort;    // 目的端口号,2B
	unsigned char Protocol;       //协议类型，1B

}Quintet_t;

typedef struct Src_Des_IP
{
    unsigned long SIP;
    unsigned long DIP;
}Src_Des_IP_t;

typedef struct Src_IP
{
    unsigned long SrcIP;
}SrcIP_t;


int main()
{
    struct pcap_pkthdr *ptk_header = NULL;
    FramHeader_t *eth_header = NULL;
    IPHeader_t *ip_header = NULL;
    TCPHeader_t *tcp_header = NULL;
    UDPHeader_t *udp_header = NULL;
    Quintet_t *quintet = NULL;
    Src_Des_IP_t *src_des_IP=NULL;
    SrcIP_t *src_ip=NULL;

    //初始化
    ptk_header  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    eth_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
    quintet = (Quintet_t *)malloc(sizeof(Quintet_t));
    src_des_IP=(Src_Des_IP_t*)malloc(sizeof(Src_Des_IP_t));
    src_ip=(SrcIP_t*)malloc(sizeof(SrcIP_t));
    //memset(buf, 0, sizeof(buf));//memset函数是初始化函数，memset(首地址，值，sizeof(地址总大小）），将连续的内存初始化为某个值（以字节为单位）
	FILE* pFile = fopen( "trace1.pcap", "rb");
	FILE *FIVE_TUPLES = fopen("five_tuples.dat","wb");
    FILE *SRC_DST_IP = fopen("src+dst IP.dat","wb");
    FILE *SRC_IP = fopen("src ip.dat","wb");

    int flag=0;

    cout<<"\n来，你瞅瞅你要嘎哈：\n";
    cout<<"\n我要五元组               ——————  按0\n"<<"我要(源+目)IP            ——————  按1\n"<<"我要源IP                 ——————  按2\n"<<"我太贪了，三种都要       ——————  按3\n"<<"\n说吧，选啥：";
    cin>>flag;
    //开始读数据包
    printf("\n--------开始读数据包-------\n");
    long int pkt_offset;	//用来文件偏移
    pkt_offset = 24;       //pcap文件头结构 24个字节
    int pkt_num=1;
    long dat_pkt_num=1;//写入dat文件中的数据包总数
    fseek(pFile,24,SEEK_SET);

    for(pkt_num=1;pkt_num<WireShark_Total_PacketNums+1;pkt_num++) //跳过pcap文件头,该函数是指对于pFile这个文件，从SEEK_SET（文件的开头）这个位置开始偏移pkt_offset个字节
    {
        //fseek(pFile,pkt_offset,SEEK_SET);
        //cout<<dec<<ftell(pFile)<<"\n";
        memset(ptk_header, 0, sizeof(struct pcap_pkthdr));
        memset(quintet,0,sizeof(struct Quintet));
        memset(src_des_IP,0,sizeof(struct Src_Des_IP));
        memset(src_ip,0,sizeof(struct Src_IP));
        memset(ip_header, 0, 20);
        memset(tcp_header,0,20);
        memset(udp_header,0,8);

        fread(ptk_header, 16, 1, pFile);//读pcap数据包头结构（16B）  从pFile中读取1个单元，单元的大小为16个字节，将读取的数据放到ptk_header中，然后文件流的指针移动1*16个字节
        //cout<<"当前数据包的数据区长度为："<<hex<<ptk_header->caplen<<"个字节\n****";
        //cout<<dec<<ftell(pFile)<<"\n";
        //pkt_offset+=16+int(ptk_header->caplen);   //下一个数据包的偏移值
        //cout<<pkt_offset<<"\n";
        //cout<<ptk_header->caplen;

        fread(ip_header, 20, 1, pFile);
        //cout<<hex<<ip_header->Protocol;

        if(ip_header->Ver_HLen==0x45 and (ip_header->Protocol==0x06||ip_header->Protocol==0x11))//判断是否是 TCP 协议
        {
            //情况0时的赋值
            quintet->SrcIP = ip_header->SrcIP;
            quintet->DstIP = ip_header->DstIP;
            quintet->Protocol = ip_header->Protocol;

            //情况1时的赋值
            src_des_IP->SIP=ip_header->SrcIP;
            src_des_IP->DIP=ip_header->DstIP;

            //情况2时的赋值
            src_ip->SrcIP=ip_header->SrcIP;

            if(ip_header->Protocol==0x06)
            {
                fread(tcp_header,20,1,pFile);
                //fseek(pFile,ptk_header->caplen+16,SEEK_CUR);
                quintet->SrcPort = tcp_header->SrcPort;
                quintet->DstPort = tcp_header->DstPort;
                if(fseek(pFile,ptk_header->caplen-40,1)!=0) cout<<"error";
            }

            else
            {
                fread(udp_header,8,1,pFile);
                //fseek(pFile,ptk_header->caplen+16,SEEK_CUR);
                quintet->SrcPort = udp_header->SrcPort;
                quintet->DstPort = udp_header->DstPort;
                if(fseek(pFile,ptk_header->caplen-28,1)!=0) cout<<"error";
            }
            if(flag==0)
            {

                fwrite(quintet,13,1,FIVE_TUPLES);
                cout<<"*******************************\n";
                cout<<"写入dat文件第"<<dec<<dat_pkt_num<<"个数据包的信息：\n";
                cout<<"源IP:"<<hex<<quintet->SrcIP<<"\n";
                cout<<"目的IP:"<<hex<<quintet->DstIP<<"\n";
                cout<<"协议类型:"<<hex<<int(quintet->Protocol)<<"\n";
                cout<<"源端口:"<<hex<<quintet->SrcPort<<"\n";
                cout<<"目的端口:"<<hex<<quintet->DstPort<<"\n";
                cout<<"\n*******************************\n";
                dat_pkt_num++;
            }
            else if(flag==1)
            {

                fwrite(src_des_IP,8,1,SRC_DST_IP);
                cout<<"\n*******************************\n";
                cout<<"写入dat文件第"<<dec<<dat_pkt_num<<"个数据包的信息：\n";
                cout<<"源IP:"<<hex<<src_des_IP->SIP<<"\n";
                cout<<"目的IP:"<<hex<<src_des_IP->DIP<<"\n";
                cout<<"*******************************\n";
                dat_pkt_num++;
            }
            else if(flag==2)
            {
                fwrite(src_ip,4,1,SRC_IP);
                cout<<"\n*******************************\n";
                cout<<"写入dat文件第"<<dec<<dat_pkt_num<<"个数据包的信息：\n";
                cout<<"源IP:"<<hex<<src_ip->SrcIP<<"\n";
                cout<<"\n*******************************\n";
                dat_pkt_num++;
            }
            else if(flag==3)
            {
                fwrite(quintet,13,1,FIVE_TUPLES);
                fwrite(src_des_IP,8,1,SRC_DST_IP);
                fwrite(src_ip,4,1,SRC_IP);
                dat_pkt_num++;
                cout<<"在搞呢，别着急呀！！\n";
            }
        }
        else
        {
            fseek(pFile,ptk_header->caplen-20,1);
            continue;
        }
    } // end while
    fclose(pFile);
    fclose(FIVE_TUPLES);
    fclose(SRC_DST_IP);
    fclose(SRC_IP);

    printf("\n-------整完了，滚蛋吧，揣好别丢喽!-------\n");
    cout<<"\n数据包总数为：";
    cout<<dec<<pkt_num-1;
    cout<<"个\n";
    cout<<"写入dat文件的数据包总数为："<<dec<<dat_pkt_num-1;
    
}


