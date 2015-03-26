URL="http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip"
wget -q $URL -O db.zip
unzip -q db.zip
rm -f db.zip

URL="http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2v6.zip"
wget -q $URL -O db.zip
unzip -q db.zip
rm -f db.zip
