#!/bash/bin

for d in $(cat target.txt); do

#waymore -i $d -mode U -oU w.txt;

waybackurls $d > wayback.txt

echo $d | gau > gau.txt

##paramspider -d $d

python github-endpoints.py -t your-github-api-key-value -d $d >> github-urls.txt

done

cat wayback.txt gau.txt github-urls.txt > f.txt

cat f.txt | httpx -silent -o turls.txt

cat turls.txt | grep "=" > p.txt

cat p.txt | uro > params.txt

cat turls.txt | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt

rm -r wayback.txt gau.txt
#rm -r w.txt
rm -r p.txt
rm -r f.txt
