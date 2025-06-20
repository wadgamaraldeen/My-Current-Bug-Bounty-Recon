#!/bash/bin

for url in $(cat domains.txt); do

subfinder -d $url -all >> subfinder.txt;

amass enum -passive -norecursive -noalts -d $url >> amass.txt;

echo $url | assetfinder --subs-only >> asset.txt;

python github-subdomains.py -t your-github-api-key-value -d $url | grep -v '@' | sort -u | grep "\.$url" >> github-subs.txt

 curl -s https://crt.sh/?q=%25.$url | grep $url | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u >> crt.txt

done

 cat subfinder.txt amass.txt asset.txt crt.txt | anew all-subs.txt

 rm -r subfinder.txt amass.txt asset.txt crt.txt

 cat all-subs.txt | httpx -o live-subs.txt

 #rm -r all-subs.txt
