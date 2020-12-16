package main

// support ipv4 ipv6  udp
// not support tcp

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"sync/atomic"

	//"net"
	"runtime"
	"time"
)

var (
	dname               string
	snapshot_len        int32  = 6000 //1024
	promiscuous         bool   = true
	err                 error
	timeout             time.Duration = 30 * time.Second
	handle              *pcap.Handle
	count               uint64
	syslogaddress       string
)

func main() {
	flag.StringVar(&dname, "device_name", "en4","sniff device name")
	flag.StringVar(&dname, "n", "en4","sniff device name")
	flag.StringVar(&syslogaddress, "syslog_address", "127.0.0.1:30051","output rsyslog address")
	flag.StringVar(&syslogaddress, "address", "127.0.0.1:30051","output rsyslog address")
	flag.Parse()
	// 得到所有的(网络)设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// 查找本地设备
	var Ldev = false
	for _, device := range devices {
		//log.Println("Name: ", device.Name)
		//fmt.Println(reflect.TypeOf(device.Name))
		if device.Name == dname {
			Ldev = true
			log.Println("\nName: ", device.Name)
		}
	}
	if Ldev == false {
		fmt.Println("dev Name error, Local dev not found.")
	}

	// Open device
	handle, err = pcap.OpenLive(dname, snapshot_len, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	// Set filter
	var filter string = "dst port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing dst port 53 packets.")

	conn,err := net.Dial("tcp",syslogaddress)
	if err != nil{
		log.Println("syslog dial err：",err)
		return
	}

	go func() {
		for {
			t1 := time.Now().Unix()
			fmt.Println("time: ", t1, " count: ", count)
			atomic.SwapUint64(&count, 0)
			time.Sleep(1 * time.Second)
		}
	}()

	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}

		go func() {
			var eth layers.Ethernet
			var ip4 layers.IPv4
			var ip6 layers.IPv6
			var tcp layers.TCP
			var udp layers.UDP
			var dns layers.DNS
			var SrcIP string
			//var DstIP string
			var qname string
			var payload gopacket.Payload

			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

			decodedLayers := make([]gopacket.LayerType, 0, 20000)

			err = parser.DecodeLayers(data, &decodedLayers)
			if err != nil {
				runtime.Goexit()
			}
			for _, typ := range decodedLayers {
				switch typ {
				case layers.LayerTypeIPv4:
					SrcIP = ip4.SrcIP.String()
					//DstIP = ip4.DstIP.String()
				case layers.LayerTypeIPv6:
					SrcIP = ip6.SrcIP.String()
					//DstIP = ip6.DstIP.String()
				case layers.LayerTypeDNS:
					qname = string(dns.Questions[0].Name)
				}
				if (len(SrcIP) != 0 && len(qname) != 0) {
					var msg  map[string]string
					msg = make(map[string]string)
					msg["queryname"] = qname
					msg["clientip"] = SrcIP
					atomic.AddUint64(&count,1)
					data,err := json.Marshal(msg)
					if err != nil{
						log.Println("json marshal failed,err:",err)
						return
					}
					//log.Println("srcIP: " + SrcIP + " DstIP: " + DstIP + " qname: " + qname + " json data:" + string(data))
					_, err = conn.Write(data)
					if err != nil{
						log.Println("conn Write err:",err)
					}
					_, err = conn.Write([]byte("\n"))
					if err != nil{
						log.Println("conn Write err:",err)
					}
				}
			}
			runtime.Goexit()
		}()
	}
}