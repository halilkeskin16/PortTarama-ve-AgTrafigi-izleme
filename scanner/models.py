from django.db import models


class IPAdresleri(models.Model):
    ip_id = models.AutoField(primary_key=True)
    ip_adresi = models.CharField(max_length=15)
    islem_tarihi = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.ip_adresi} {self.ip_adresi} "

class Ports(models.Model):
    port_id = models.AutoField(primary_key=True)
    port = models.CharField(max_length=5)
    servis_name = models.CharField(max_length=20)
    ip_adresi = models.ForeignKey(IPAdresleri,on_delete=models.CASCADE)

    def __str__(self):
        return f"Port: {self.port} - IP Adresi: {self.ip_adresi.ip_adresi}"
class Scapy_Veri(models.Model):
    icerik_id = models.AutoField(primary_key=True)
    icerik = models.TextField()