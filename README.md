# AI Destekli Ağ Saldırı Tespit Sistemi

Python, Random Forest ve kural tabanlı analiz kullanan bir ağ saldırı tespit laboratuvar prototipi. Streamlit paneli üzerinden trafik kaydı başlatılır; kayıt tamamlandıktan sonra akışlar analiz edilir ve geçmiş sonuçlar görüntülenir.

**Durum:** çalışan laboratuvar prototipi. Otomatik engelleme yapmaz; sürekli gerçek zamanlı bir IPS değildir. Model tahminleri kesin saldırı kanıtı değildir.

## Özellikler

- Panelden ağ arayüzü ve kayıt süresi seçimi
- tcpdump ile PCAP kaydı, CICFlowMeter ile akış çıkarımı
- BENIGN, PortScan ve DDoS model tahminleri
- Aynı kaynak-hedef çifti için 10 saniyede en az 20 farklı TCP hedef portuna SYN girişimini algılayan ayrı kural
- Geçmiş kayıt listesi, grafikler, akış tablosu ve CSV indirme
- PCAP, özellik CSV’si, tahmin CSV’si ve TXT özeti saklama

## Son doğrulanmış testler

VirtualBox üzerinde iki Kali Linux ile kontrollü TCP bağlantı taraması ve ayrı normal web gezinmesi denemesi yapılmıştır.

| Test | Model | Tarama kuralı |
|---|---|---|
| 100 tarama akışı | 86 PortScan, 13 BENIGN, 1 DDoS | 100 farklı port, 1 uyarı |
| Ayrı normal gezinme kaydı: 92 akış | 92 BENIGN | 0 uyarı |

Tarama kaydında toplam 132 akış vardır. Yukarıdaki 100 akış kaynak/hedef IP, TCP ve taranan hedef port aralığıyla ayrılmıştır. Kalan 32 akış BENIGN tahmin edilmiştir. %86 yalnızca bu kontrollü deneyde tarama türünün tanınma oranıdır; genel doğruluk oranı değildir. Önceki normal trafik deneylerinde yanlış alarmlar görülmüştür. DDoS başarımı bu son testlerle doğrulanmamıştır.

## Çalışma akışı

Panel `izle.py` çalıştırır. `tcpdump` trafiği kaydeder. `cicflowmeter` PCAP’tan akışları çıkarır. Model tahminleri ve ayrı tarama kuralının çıktısı kaydedilir. Paneldeki saldırı sayacı model tahminidir; kural sonucu ayrıca gösterilir.

## Mevcut proje ortamında çalıştırma

```bash
cd ~/Downloads/ai-network-ids
source .venv/bin/activate
python -m streamlit run panel.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Aynı makinede http://127.0.0.1:8501 adresini açın. `eth0` ağ trafiği, `lo` yerel makine testleri içindir. Arayüz adını `ip -br a` ile kontrol edin. Panel 5-300 saniye kayıt süresi destekler. Paket yakalama için uygun yetki gerekir; laboratuvar root hesabıyla çalıştırılmıştır.

Terminalden:

```bash
python izle.py --interface eth0 --seconds 30
python tarama_kontrol.py kayitlar/KAYIT_ID/trafik.pcap
python pencere_ozellikleri.py kayitlar/KAYIT_ID/trafik.pcap
```

`KAYIT_ID` gerçek kayıt klasörüyle değiştirilmelidir. Pencere çıkarıcı mevcut CSV üzerine yazmaz.

## Yeni ortam kurulumu

Sistem araçları: Python 3, venv, tcpdump ve GNU coreutils içindeki timeout. Laboratuvarda Python 3.14 kullanılmıştır.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

**Bu kurulum tek başına doğrulanmış ortamı yeniden üretmez.** Tam bağımlılık sürüm kilidi alınmamıştır. Hazır joblib modelleri scikit-learn sürüm farklarından etkilenebilir. Yeni ortamda sonuçlar ayrıca doğrulanmalıdır. Yalnızca güvenilir kaynaklardan gelen joblib dosyalarını yükleyin.

`duzeltmeler/cicflowmeter/` altında kurulu cicflowmeter 0.5.0 için kullanılan iki değiştirilmiş dosya bulunmaktadır:

1. `flow_session.py`: yeni akışın ilk paketinin iki kez eklenmesini önler.
2. `sniffer.py`: tek PCAP dosyası okunurken gerçek saat kullanan arka plan temizliğini başlatmaz.

Kurulu paketin aynı sürüm olduğunu doğrulayıp mevcut dosyaları yedekleyerek bu dosyaları ilgili paket dizinine uygulamak gerekir. Farklı sürümün üzerine doğrudan kopyalanmamalıdır. Dosyalar kendiliğinden uygulanmaz. Doğrudan canlı dinleme ve toplu birleştirme yollarının tüm eşzamanlılık sorunlarının giderildiği iddia edilmemektedir. Proje önce PCAP kaydeder, ardından tek dosya analizi yapar.

## Modeller

| Dosya | Rol |
|---|---|
| `models/gelistirilmis_model.joblib` | Panelin kullandığı aktif dört özellikli model |
| `models/ddos_model.joblib`, `models/uc_sinif_model.joblib` | Önceki CIC-IDS2017 CSV deneyleri |
| `models/ortak_model.joblib`, `models/portsuz_model.joblib` | Özellik karşılaştırma deneyleri |
| `models/yerel_model_v1.joblib` | Yerel akış deneyi; tek normal başarısız bağlantıda yanlış alarm verdi |
| `models/davranis_model_v1.joblib` | Deneysel 10 saniyelik davranış penceresi modeli; panele bağlı değil |

Aktif model hedef port, ileri/geri paket sayısı ve akış süresini kullanır. Süre `izle.py` içinde saniyeden mikrosaniyeye dönüştürülür. Yerel model saniye kullanır; deneysel modeller aktif model dosyasıyla doğrudan yer değiştiremez.

Davranış modelinde bildirilen test 20 normal ve 1 tarama penceresidir. Eğitimde yalnızca 1 tarama penceresi vardır; sonuç genel başarı kanıtı değildir. Örtüşen pencereler bağımsız örnek gibi yorumlanmamalıdır.

## Dosyalar ve veri

- `train.py`: etiketli CSV ile temel Random Forest eğitimi; rastgele satır bölmesi kullanır.
- `predict.py`, `alert.py`: CSV üzerinden önceki tahmin/uyarı araçları.
- `izle.py`: yakalama, dönüşüm, aktif model ve kural çalıştırma.
- `panel.py`: Streamlit arayüzü.
- `tarama_kontrol.py`: IPv4 TCP tarama kuralı.
- `pencere_ozellikleri.py`: SYN, farklı bağlantı/port ve tekrar özellikleri.
- `docs/Proje-Raporu.pdf`: inceleme raporu ve kullanım kılavuzu.

Kayıtlar `kayitlar/<oturum>/` altında `trafik.pcap`, `akislar.csv`, `sonuclar.csv`, `ozet.txt` dosyalarıyla saklanır. Ham trafik ve eğitim veri kümeleri bu depoya dahil edilmemiştir. Otomatik saklama süresi veya silme politikası yoktur.

## Sınırlar

Eğitim CSV’leri ile canlı akış çıkarıcısının bazı özellik tanımları farklıdır. Yüksek CSV test skoru canlı ağ başarısını garanti etmez. Normal bağlantı hataları yanlış alarma yol açabilir. Kural IPv4 TCP ile sınırlıdır; yavaş taramalar, UDP ve IPv6 kapsam dışıdır. Ağın tamamını görmek için uygun yakalama konumu gerekir; bir VM arayüzünde görülen trafik tüm ağ trafiği değildir.

Model geliştirmede CIC-IDS2017 veri kümesi ve açık kaynak Python araçlarından yararlanılmıştır. Veri kümesi depoda dağıtılmamaktadır. `duzeltmeler` içindeki üçüncü taraf dosyalar ilgili upstream projenin lisans koşullarına tabidir. Bu depoda proje sahibinin seçtiği ayrıca bir açık kaynak lisansı henüz bulunmamaktadır.
