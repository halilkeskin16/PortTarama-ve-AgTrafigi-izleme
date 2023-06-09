
from django.urls import path
from.import views    # vievw sayfanıa erişim için
 
#http://127.0.0.1:8000/  = Anasayfa



urlpatterns = [    
    path("",views.ip_detay),
    path('/detay', views.port_scan, name='port_scan'),
    path('/dinleme',views.dinleme,name='dinleme'),

]
