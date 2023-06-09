from django.shortcuts import render
from django.utils import timezone
import nmap
from scanner.models import IPAdresleri, Ports, Scapy_Veri
from scapy.all import *
import json
from django.http import JsonResponse

def port_scan(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        nm = nmap.PortScanner()
        nm.scan(hosts=str(ip_address), arguments='-sS -p 1-100 ')
        result = []

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                ip_result = {
                    'ip_adresi': host,
                    'durumu': nm[host].state(),
                    'protokoller': [],
                }

                for protocol in nm[host].all_protocols():
                    protocol_result = {
                        'protocol': protocol,
                        'portlar': [],
                    }

                    port_dict = nm[host][protocol]
                    for port in port_dict.keys():
                        port_state = port_dict.get(port)
                        if port_state is not None:
                            servis = port_state['name']
                            port_result = {
                                'port': port,
                                'durum': port_state['state'],
                                'kullanilan_servis': port_state['name'],
                            }
                            protocol_result['portlar'].append(port_result)
                        else:
                            protocol_result['portlar'].append({'port': 'Port bulunamadı'})
                    
                    ip_result['protokoller'].append(protocol_result)
                
                result.append(ip_result)
        
        return JsonResponse(result, safe=False)

def ip_detay(request):
    return render(request,'detay.html')

def dinleme(request):
    if request.method == "POST":
        sonuc = []
        ag_turu = request.POST.get('agturu')
        paket_sayisi = request.POST.get('paketdegeri')
        def ag_dinleme(packet): 
            sonuc.append(packet.show(dump=True))                                                #dump=True gelen paketi dizi olarak almaya yarar.
        sniff(iface = str(ag_turu), prn =ag_dinleme , count = int(paket_sayisi) , store = 0)    #count degeri kac tane tarama yapdığınızı belirtir 0 sonsuz taramadır.                                                                                            #store ile gelen paketlerin kaydedilip kaydedilmemesini sağlar 0 değeri kayd
        _sonuc = Scapy_Veri.objects.create(icerik=sonuc)
        _sonuc.save()
        return render(request,"detay.html",{"sonuc": sonuc })
     
    return render (request,'detay.html')








