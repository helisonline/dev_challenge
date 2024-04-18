from scapy.all import *

def tcp_scan(dst_ip, dport):
    """ Checa se o host de destino está ativo e se a porta de destino está aberta e enviando pacotes
    
    Argumentos:
        dst_ip ([str])
        dport ([int])
    
    """

    pkt = IP (dst=dst_ip) / TCP(dport=dport)
    ans,unans = sr(pkt, timeout=1, verbose=0)
    target = sr(IP(dst=dst_ip)/TCP(dport=[dport]),inter=0.5,retry=-2,timeout=1)

    """
        Tags para exibição de estatísticas específicas sobre os pacotes
    """
    
    prot = pkt[IP].proto
    timetl = pkt[IP].ttl
    origem = pkt[IP].src
    destino = pkt[IP].dst
    protcp = pkt[TCP].dport
    janela = pkt[TCP].window


    if not ans:
        print (f"Este host {dst_ip} está offline!")
    else:
        for snd, rcv in ans:
            if rcv[TCP].flags == "SA":
                print (f"A Porta {dport} do host {dst_ip} está aberta")
                print (f"Estatísticas: Protocolo {prot}, TTL {timetl}, Origem: {origem}, Destino: {destino}, Protocolo TCP: {protcp}, {janela}")
                print (f"Resultados dos pacotes enviados: {target}")
            else:
                print (f"A porta {dport} do host {dst_ip} está fechada mas o host está ativo")
                print (f"Estatísticas: Protocolo {prot}, TTL {timetl}, Origem: {origem}, Destino: {destino}, Protocolo TCP: {protcp}, {janela}")

    """
        Alguns exemplos de IPs com suas respectivas portas
    """

tcp_scan('192.168.15.7', 80)
tcp_scan('192.168.15.7', 22)
tcp_scan('142.251.129.99', 22)
tcp_scan('192.168.15.1', 80)
tcp_scan('192.168.15.1', 22)
tcp_scan('172.217.30.14', 80)
tcp_scan('172.217.30.14', 22)
tcp_scan('0.0.0.0', 80)
tcp_scan('192.168.0.1', 80)