package main

import (
	"fmt"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Interface string `short:"i" long:"interface" description:"Interface to listen on" required:"true"`
	Args      struct {
		Filter string `description:"A tcpdump filter expression to select the connections to kill"`
	} `positional-args:"yes"`
}

func main() {
	var opts Options

	p := flags.NewParser(&opts, flags.Default)
	_, err := p.Parse()
	if err != nil {
		os.Exit(1)
	}
	handle, err := pcap.OpenLive(opts.Interface, 65535, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	//Exclude SYN, FIN or RST packets
	var filter string
	if opts.Args.Filter != "" {
		filter = fmt.Sprintf("(%s) and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) == 0)", opts.Args.Filter)
	} else {
		filter = "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) == 0"
	}

	err = handle.SetBPFFilter(filter)

	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for packet := range packets {
		rstPkt, err := generateRSTPacket(packet)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		err = handle.WritePacketData(rstPkt.Data())
		if err != nil {
			panic(err)
		}
		fmt.Println(rstPkt)
	}

}

func generateRSTPacket(packet gopacket.Packet) (rstPkt gopacket.Packet, err error) {

	var eth *layers.Ethernet
	var ipv4 *layers.IPv4
	var ipv6 *layers.IPv6
	var tcp *layers.TCP

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		eth, _ = ethernetLayer.(*layers.Ethernet)
	}
	if networkV4Layer := packet.Layer(layers.LayerTypeIPv4); networkV4Layer != nil {
		ipv4, _ = networkV4Layer.(*layers.IPv4)
	}
	if networkV6Layer := packet.Layer(layers.LayerTypeIPv6); networkV6Layer != nil {
		ipv6, _ = networkV6Layer.(*layers.IPv6)
	}
	if ipv4 == nil && ipv6 == nil {
		return nil, fmt.Errorf("not an ipv4 or ipv6 packet: %s", packet)
	}
	if transportLayer := packet.Layer(layers.LayerTypeTCP); transportLayer != nil {
		tcp, _ = transportLayer.(*layers.TCP)
	} else {
		return nil, fmt.Errorf("not a tcp packet: %s", packet)
	}

	rstPacket := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	var pktLayers []gopacket.SerializableLayer

	if eth != nil {
		ethSrc := eth.SrcMAC
		eth.SrcMAC = eth.DstMAC
		eth.DstMAC = ethSrc
		pktLayers = append(pktLayers, eth)
	}
	if ipv4 != nil {
		ipSrc := ipv4.SrcIP
		ipv4.SrcIP = ipv4.DstIP
		ipv4.DstIP = ipSrc
		_ = tcp.SetNetworkLayerForChecksum(ipv4)
		pktLayers = append(pktLayers, ipv4)
	} else {
		ipSrc := ipv6.SrcIP
		ipv6.SrcIP = ipv6.DstIP
		ipv6.DstIP = ipSrc
		_ = tcp.SetNetworkLayerForChecksum(ipv6)
		pktLayers = append(pktLayers, ipv6)
	}

	tcp.RST = true
	tcpSrc := tcp.SrcPort
	tcp.SrcPort = tcp.DstPort
	tcp.DstPort = tcpSrc
	newAck := tcp.Seq + uint32(len(tcp.Payload))
	tcp.Seq = tcp.Ack
	tcp.Ack = newAck

	pktLayers = append(pktLayers, tcp)

	err = gopacket.SerializeLayers(rstPacket, opts, pktLayers...)
	if err != nil {
		return nil, err
	}

	rstPkt = gopacket.NewPacket(rstPacket.Bytes(), pktLayers[0].LayerType(), gopacket.Default)
	return rstPkt, nil
}
