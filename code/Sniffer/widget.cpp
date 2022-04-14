#include "widget.h"
#include "ui_widget.h"

#include <QDebug>
#include <QPushButton>
#include <QTimer>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/types.h>



#define PROM 1

#ifndef SNIFFER_PROTOCOL_H
#define SNIFFER_PROTOCOL_H

#define snapLen 1518





#define arpRequest 1
#define arpReply 2


#define tcpFIN 0x01
#define tcpSYN 0x02
#define tcpRST 0x04
#define tcpPSH 0x08
#define tcpACK 0x10
#define tcpURG 0x20
#define tcpECE 0x40
#define tcpCWR 0x80


#define ethernetHead 14

#define ethernetAddr 6

struct ethernet
{
    u_char etherHostD[ethernetAddr];
    u_char etherHostS[ethernetAddr];
    u_short etherType;
};

char filter[128];
char *dev;
int tcpFlow, udpFlow, icmpFlow;
int tcpCnt, udpCnt, icmpCnt;



int flowTotal = 0;
int ipv4Flow = 0, ipv6Flow = 0, arpFlow = 0, rarpFlow = 0, pppFlow = 0;
int ipv4Cnt = 0, ipv6Cnt = 0, arpCnt = 0, rarpCnt = 0, pppCnt = 0;

int otherCnt = 0, otherFlow = 0;


QString errClr = "de7e73";
QString highClr = "A593E0";

u_int id = 0;

#define ipHead(packet) ((((struct ip *)(packet + ethernetHead)) -> ipHV & 0x0f) * 4)

#define ipAddr 4

struct ip
{
    u_char ipHV;

    u_char ipTos;
    u_short ipLen;
    u_short ipId;
    u_short ipOffset;
    u_char ipTtl;
    u_char ipProtocol;
    u_short ipCkSum;
    u_char ipS[ipAddr];
    u_char ipD[ipAddr];
};

struct tcp
{
    u_short tcpS;
    u_short tcpD;
    u_int tcpSeq;
    u_int tcpAck;
    u_char tcpHR;

    u_char tcpFlag;
    u_short tcpWin;
    u_short tcpCkSum;
    u_short tcpUrgP;
};

struct udp
{
    u_short udpS;
    u_short udpD;
    u_short udpLen;
    u_short udpCkSum;
};

struct arp
{
    u_short arpHardware;
    u_short arpProtocol;
    u_char arpMac;
    u_char arpIp;
    u_short arpOperation;
    u_char arpSM[ethernetAddr];
    u_char arpSI[ipAddr];
    u_char arpDM[ethernetAddr];
    u_char arpDI[ipAddr];
};

struct icmp
{
    u_char icmpType;
    u_char icmpCode;
    u_short icmpCkSum;
    u_short icmpFlag;
    u_short icmpSeq;
    u_int icmpTime;
};

struct ppp
{
    u_char pppVT;

    u_char pppCode;
    u_short pppSessionId;
    u_short pppLen;
};

#endif

QString pppAnalyze(const u_char *packet)
{
    struct ppp *pHead = (struct ppp *)(packet + ethernetHead);

    QString packet_cache;
    packet_cache.clear();
    char tmp[70] = {0};

     sprintf(tmp, "Version: %d\n", (pHead -> pppVT & 0xf0) >> 4);
    packet_cache += tmp;

    sprintf(tmp, "Type: %d\n", pHead -> pppVT & 0x0f);
    packet_cache += tmp;

    sprintf(tmp, "Code: %d\n", pHead -> pppCode);
    packet_cache += tmp;

     sprintf(tmp, "Session ID: %d\n", ntohs(pHead -> pppSessionId));
    packet_cache += tmp;

    sprintf(tmp, "Payload Length: %d\n", ntohs(pHead -> pppLen));
    packet_cache += tmp;

    return packet_cache;
}


QString arpAnalyze(const u_char *packet)
{
    struct arp *aHead = (struct arp *)(packet + ethernetHead);

    QString packet_cache;
    packet_cache.clear();
    char tmp[70] = {0};

    if(ntohs(aHead -> arpHardware) == 0x0001)
    {
        sprintf(tmp, "Hardware type: %s\n", "Ethernet");
    }
    else
    {
        sprintf(tmp, "Hardware type: %s\n", "Unknown");
    }
    packet_cache += tmp;

    if(ntohs(aHead -> arpProtocol) == 0x0800)
    {
        sprintf(tmp, "Protocol type: %s\n", "IPv4");
    }
    else
    {
         sprintf(tmp, "Protocol type: %s\n", "Unknown");
    }
    packet_cache += tmp;

    if(ntohs(aHead -> arpOperation) == arpRequest)
    {
        sprintf(tmp, "Operation: %s\n", "ARP request");
    }
    else
    {
        sprintf(tmp, "Operation: %s\n", "ARP reply");
    }
    packet_cache += tmp;


    packet_cache += "MAC source: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
         sprintf(tmp, "%02x:", aHead -> arpSM[i]);
        packet_cache += tmp;
    }

    packet_cache += "\nMAC destination: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
         sprintf(tmp, "%02x: ", aHead -> arpDM[i]);
        packet_cache += tmp;
    }

    packet_cache += "\nIP source";
    for(int i = 0; i < ipAddr; i++)
    {
        sprintf(tmp, "%d.", aHead -> arpSI[i]);
        packet_cache += tmp;
    }

    packet_cache += "\nIP destination";
    for(int i = 0; i < ipAddr; i++)
    {
        sprintf(tmp, "%d.", aHead -> arpDI[i]);
        packet_cache += tmp;
    }

    return packet_cache;
}


QString icmpAnalyze(const u_char *packet)
{
    struct icmp *icmpHead = (struct icmp *)(packet + ethernetHead + ipHead(packet));
    u_char icmpType = icmpHead -> icmpType;

    QString packet_cache;
    packet_cache.clear();
    char tmp[70] = {0};

    sprintf(tmp, "ICMP type: %d  ", icmpHead -> icmpType);
    packet_cache += tmp;
    switch (icmpType)
    {
    case 0x08:
        packet_cache += "(ICMP request)\n";
        break;
    case 0x00:
        packet_cache += "(ICMP response)\n";
        break;
    case 0x11:
        packet_cache += "(Timeout!)\n";
        break;
    }
    sprintf(tmp, "ICMP code: %d\n", icmpHead -> icmpCode);
    packet_cache += tmp;

    sprintf(tmp, "ICMP check summary: %d\n", icmpHead -> icmpCkSum);
    packet_cache += tmp;

    return packet_cache;
}


char *tcpFlagAnalyze(const u_char tcpFlags)
{
    char flags[100] = "";
    if((tcpCWR & tcpFlags) == tcpCWR)
        strncat(flags, "CWR: ", 100);
    if((tcpECE & tcpFlags) == tcpECE)
        strncat(flags, "ECE: ", 100);
    if((tcpURG & tcpFlags) == tcpURG)
        strncat(flags, "URG: ", 100);
    if((tcpACK & tcpFlags) == tcpACK)
        strncat(flags, "ACK: ", 100);
    if((tcpPSH & tcpFlags) == tcpPSH)
        strncat(flags, "PSH: ", 100);
    if((tcpRST & tcpFlags) == tcpRST)
        strncat(flags, "RST: ", 100);
    if((tcpSYN & tcpFlags) == tcpSYN)
        strncat(flags, "SYN: ", 100);
    if((tcpFIN & tcpFlags) == tcpFIN)
        strncat(flags, "FIN: ", 100);
    flags[99] = '\0';
    return flags;
}


QString tcpAnalyze(const u_char *packet)
{
    struct tcp *tHead = (struct tcp *)(packet + ethernetHead + ipHead(packet));

    QString packet_cache;
    packet_cache.clear();
    char tmp[70] = {0};

    sprintf(tmp, "Source port: %d\n", ntohs(tHead -> tcpS));
    packet_cache += tmp;

    sprintf(tmp, "Destination port: %d\n", ntohs(tHead -> tcpD));
    packet_cache += tmp;

    sprintf(tmp, "Sequence number: %d\n", ntohs(tHead -> tcpSeq));
    packet_cache += tmp;

    sprintf(tmp, "Acknowledge number: %d\n", ntohs(tHead -> tcpAck));
    packet_cache += tmp;

    sprintf(tmp, "Header length: %d\n", (tHead -> tcpHR & 0xf0) >> 4);
    packet_cache += tmp;

    sprintf(tmp, "Flag: %d\n", tHead -> tcpFlag);
    packet_cache += tmp;

    sprintf(tmp, "Flags: %d\n", tcpFlagAnalyze(tHead -> tcpFlag));
    packet_cache += tmp;

     sprintf(tmp, "Window: %d\n", ntohs(tHead -> tcpWin));
    packet_cache += tmp;

    sprintf(tmp, "Check summary: %d\n", ntohs(tHead -> tcpCkSum));
    packet_cache += tmp;

    sprintf(tmp, "Urgent pointer: %d\n", ntohs(tHead -> tcpUrgP));
    packet_cache += tmp;

    return packet_cache;
}


QString udpAnalyze(const u_char *packet)
{
    struct udp *uHead = (struct udp *)(packet + ethernetHead + ipHead(packet));

    QString packet_cache;
    packet_cache.clear();
    char tmp[70] = {0};

    sprintf(tmp, "Source port: %d\n", ntohs(uHead -> udpS));
    packet_cache += tmp;

    sprintf(tmp, "Destination port: %d\n", ntohs(uHead -> udpD));
    packet_cache += tmp;

    sprintf(tmp, "UDP length: %d\n", ntohs(uHead -> udpLen));
    packet_cache += tmp;

    sprintf(tmp, "UDP check summary: %d\n", ntohs(uHead -> udpCkSum));
    packet_cache += tmp;

    return packet_cache;
}


QString ipAnalyze(const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct ip *ipHead;
    ipHead = (struct ip *)(packet + ethernetHead);

    QString packet_cache;
    packet_cache.clear();
    char tmp[50] = {0};

    sprintf(tmp, "Version: %d\n", (ipHead -> ipHV & 0xf0) >> 4);
    packet_cache += tmp;

    sprintf(tmp, "Head Length: %d\n", ipHead -> ipHV & 0x0f);
    packet_cache += tmp;

    sprintf(tmp, "Type of Service: %d\n", ipHead -> ipTos);
    packet_cache += tmp;

    sprintf(tmp, "Total Length: %d\n", ipHead -> ipLen);
    packet_cache += tmp;

    sprintf(tmp, "Identification: %d\n", ipHead -> ipId);
    packet_cache += tmp;

    sprintf(tmp, "Offset: %d\n", ipHead -> ipOffset & 0x1fff);
    packet_cache += tmp;

    sprintf(tmp, "Time to Live: %d\n", ipHead -> ipTtl);
    packet_cache += tmp;

    sprintf(tmp, "Protocol: %d\n", ipHead -> ipProtocol);
    packet_cache += tmp;

    sprintf(tmp, "Check Summary: %d\n", ipHead -> ipCkSum);
    packet_cache += tmp;


    packet_cache += "IP source: ";
    for(int i = 0; i < ipAddr; i++)
    {
        sprintf(tmp, "%d.", ipHead -> ipS[i]);
        packet_cache += tmp;
    }

    packet_cache += "\nIP destination: ";
    for(int i = 0; i < ipAddr; i++)
    {
        sprintf(tmp, "%d.", ipHead -> ipD[i]);
        packet_cache += tmp;
    }
    packet_cache += "\n";

    u_char protocol = ipHead -> ipProtocol;
    if(protocol == 0x01)
    {
        packet_cache += "\nICMP!\n";
        packet_cache += icmpAnalyze(packet);
        icmpCnt ++;
        icmpFlow += pcapPkt->caplen;
    }


    packet_cache += '#';
    switch (protocol)
    {
    case 0x01:
        break;
    case 0x06:
        packet_cache += "TCP!\n";
        packet_cache += tcpAnalyze(packet);
        tcpFlow += pcapPkt->caplen;
        tcpCnt ++;
        break;
    case 0x11:
        packet_cache += "UDP!\n";
        packet_cache += udpAnalyze(packet);
        udpFlow += pcapPkt->caplen;
        udpCnt ++;
        break;
    case 0x02:
        packet_cache += "IGMP!\n";
        break;
    case 0x58:
        packet_cache += "IGRP!\n";
        break;
    case 0x59:
        packet_cache += "OSPF!\n";
        break;
    default:
        packet_cache += "Other Transport Layer protocol!\n";
        break;
    }
    return packet_cache;
}



void ethernetAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    Ui::Widget *ui = (Ui::Widget *)arg;

    struct ethernet *eHead;
    u_short protocol;
    //char *time = ctime((const time_t*)&pcapPkt -> ts.tv_sec);

    int flow = pcapPkt -> caplen;
    flowTotal += flow;
    ++id;


    eHead = (struct ethernet*)packet;
    struct ip *iphead = (struct ip *)(packet + 14);
    QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow));

    protocol = ntohs(eHead -> etherType);
    switch (protocol)
    {
    case 0x0800:
        topInfo->setText(1,"IPv4");
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("IPv4"));
        switch (iphead->ipProtocol)
        {
        case 0x01:
            topInfo->setText(1,"IPv4 ICMP");
            //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("IPv4 ICMP"));
            break;
        case 0x06:
            topInfo->setText(1,"IPv4 TCP");
            break;
        case 0x11:
            topInfo->setText(1,"IPv4 UDP");
            break;
        case 0x02:
            topInfo->setText(1,"IPv4 IGMP");
            //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("IPv4 IGMP"));
            break;
        case 0x58:
            topInfo->setText(1,"IPv4 IGRP");
            break;
        case 0x59:
            topInfo->setText(1,"IPv4 OSPF");
            break;
        default:
            topInfo->setText(1,"IPv4 Other Transport Layer protocol");
            //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("Other Transport Layer protocol"));
            //packet_cache += "Other Transport Layer protocol!\n";
            break;
        }
        break;
     case 0x0806:
        topInfo->setText(1,"ARP");
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("ARP"));
         break;
    case 0x0835:
        topInfo->setText(1,"RARP");
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("RARP"));
        break;
    case 0x08DD:
        topInfo->setText(1,"IPv6");
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("IPv6"));
        break;
    case 0x880B:
        topInfo->setText(1,"PPPOE");
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("PPPOE"));;
        break;
    default:
        topInfo->setText(1,"Other network layer protocol");
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow) << QString("Other network layer protocol"));
        //packet_cache += "Other network layer protocol!\n";
        break;
    }



    ui->treeWidget->addTopLevelItem(topInfo);
    char tmp[10] = {0};
    QString packet_cache;
    for(int i = 0; i < pcapPkt->len; i++)
    {
        sprintf(tmp, "%02x ", packet[i]);
        packet_cache += tmp;
        if((i+1) % 16 ==0)
        {
            sprintf(tmp, "\n");
            packet_cache += tmp;
        }
    }
    QTreeWidgetItem *pInfo = new QTreeWidgetItem(QStringList() << "数据包内容" << packet_cache);
    topInfo->addChild(pInfo);
    packet_cache.clear();


    eHead = (struct ethernet*)packet;
    packet_cache += "Mac source: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
            packet_cache += tmp;
        }
        else
        {
            sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
            packet_cache += tmp;
        }
    }
    packet_cache += "Mac destination: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            sprintf(tmp, "%02x\n", eHead -> etherHostD[i]);
            packet_cache += tmp;
        }
        else
        {
            sprintf(tmp, "%02x:", eHead -> etherHostD[i]);
            packet_cache += tmp;
        }
    }
    QTreeWidgetItem * linkInfo = new QTreeWidgetItem(QStringList() << "数据链路层" << packet_cache);
    topInfo->addChild(linkInfo);
    packet_cache.clear();

    protocol = ntohs(eHead -> etherType);

    if(protocol == 0x8863)
    {
        pppAnalyze(packet);
        QTreeWidgetItem *pppInfo = new QTreeWidgetItem(QStringList() << "PPPOE Discovery" << packet_cache);
        topInfo->addChild(pppInfo);
        packet_cache.clear();
        pppCnt ++;
        pppFlow += flow;
    }
    if(protocol == 0x8864)
    {
        pppAnalyze(packet);
        QTreeWidgetItem *pppInfo = new QTreeWidgetItem(QStringList() << "PPPOE Session" << packet_cache);
        topInfo->addChild(pppInfo);
        packet_cache.clear();
        pppCnt ++;
        pppFlow += flow;
    }


    QStringList resList;
    QTreeWidgetItem *netInfo, *transInfo;
    switch (protocol)
    {
    case 0x0800:
        packet_cache += "IPv4!\n";
        packet_cache += ipAnalyze(pcapPkt, packet);
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1  IPv4").arg(flow)) ;
        resList = packet_cache.split('#');
        netInfo = new QTreeWidgetItem(QStringList() << "网络层" << resList[0]);
        topInfo->addChild(netInfo);
        transInfo = new QTreeWidgetItem(QStringList() << "传输层" << resList[1]);
        topInfo->addChild(transInfo);
        packet_cache.clear();
        resList.clear();
        ipv4Flow += flow;
        ipv4Cnt ++;
        break;
    case 0x0806:
        packet_cache += "ARP!\n";
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1ARP").arg(flow));
        packet_cache += arpAnalyze(packet);
        arpFlow += flow;
        arpCnt ++;
        break;
    case 0x0835:
        packet_cache += "RARP!\n";
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1RARP").arg(flow));
        rarpFlow += flow;
        rarpCnt ++;
        break;
    case 0x08DD:
        packet_cache += "IPv6!\n";
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1IPv6").arg(flow));
        ipv6Flow += flow;
        ipv6Cnt ++;
        break;
    case 0x880B:
        packet_cache += "PPPOE!\n";
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1PPPOE").arg(flow));
        pppFlow += flow;
        pppCnt ++;
        break;
    default:
        packet_cache += "Other network layer protocol!\n";
        //topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1Other").arg(flow));
        otherCnt ++;
        otherFlow += flow;
        break;
    }
    if(!packet_cache.isEmpty())
    {
        netInfo = new QTreeWidgetItem(QStringList() << "网络层" << packet_cache);
        topInfo->addChild(netInfo);
        packet_cache.clear();
    }
}


pcap_t *pcap;

void Widget::startSniffer(int num)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;
    bpf_u_int32 net;
    bpf_u_int32 mask;




    if(pcap_findalldevs(&allDev, errbuf) == -1)
    {
        ui->textBrowser->append(QString("<font color=\"#%1\"> No device has been found! </font>").arg(errClr));
    }
    dev = allDev -> name;
    ui->textBrowser->append(QString("\n").arg(highClr).arg(dev));



    pcap = pcap_open_live(dev, snapLen, PROM, 0, errbuf);
    if(pcap == nullptr)
    {
        ui->textBrowser->insertPlainText(QString("<font color=\"#%1\"> Open error: </font>").arg(errClr));
        ui->textBrowser->append(errbuf);
    }


    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        ui->textBrowser->insertPlainText(QString("<font color=\"#%1\"> Could not found netmask for device %2! </font>").arg(errClr).arg(dev));
        net = 0;
        mask = 0;
    }

    QApplication::processEvents();



    QApplication::processEvents();
    //printf("analyzebegin\n");
    pcap_loop(pcap, num, ethernetAnalyze, (u_char *) ui);
    //printf("analyze end\n");

    pcap_close(pcap);
    ui->textBrowser->append(QString("<font color=\"#%1\"> 结束 </font>\n").arg(highClr));
}



void Widget::stopSniffer()
{
    pcap_breakloop(pcap);
}


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);


    connect(ui->startBtn, &QPushButton::clicked, this, [=](){
        ui->textBrowser->append(QString("<font color=\"#%1\"> 开始 </font>").arg(highClr));

        startSniffer(200);


        QStringList cntList, flowList;
        cntList << QString::number(tcpCnt) << QString::number(udpCnt) << QString::number(arpCnt) << QString::number(rarpCnt) << QString::number(ipv4Cnt) << QString::number(ipv6Cnt) << QString::number(icmpCnt) << QString::number(pppCnt);
        flowList << QString::number(tcpFlow) << QString::number(udpFlow) << QString::number(arpFlow) << QString::number(rarpFlow) << QString::number(ipv4Flow) << QString::number(ipv6Flow) << QString::number(icmpFlow) << QString::number(pppFlow);

    });

    connect(ui->stopBtn, &QPushButton::clicked, this, [=](){
        stopSniffer();
        ui->textBrowser->append(QString("<font color=\"#%1\"> 停止 </font>").arg(highClr));
    });


    ui->treeWidget->setHeaderLabels(QStringList() << "编号" << "数据包类型");
    ui->treeWidget->setColumnWidth(0, 170);
}

Widget::~Widget()
{
    delete ui;
}

