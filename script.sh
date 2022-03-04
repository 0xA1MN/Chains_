#!/bin/bash

cat <<"EOF"

    ____ _           _           
   / ___| |__   __ _(_)_ __  ___ 
  | |   | '_ \ / _\ | | '_ \/ __|
  | |___| | | | (_| | | | | \__ \
   \____|_| |_|\__,_|_|_| |_|___/
				0xA1MN
  Automae Recon Process Using Awesome Tools.
  Twitter https://twitter.com/0xA1MN 


EOF

# check inputs
if [ -z "$1" ] && [ -z "$2" ]; then
	echo "Invalid Format ./chains.sh [scope.txt] [OutFolder] [burp collaborator | interactsh-client (optional)]"
	echo ""
  exit
else
	trap "exit" INT

	outFolder=$2
  server=$3
  RL=100 # scanners rate limit

  # File structure
	mkdir -p $HOME/$outFolder
	
	mkdir -p $HOME/$outFolder/assets
	mkdir -p $HOME/$outFolder/assets/junk
	mkdir -p $HOME/$outFolder/assets/junk/domain
	mkdir -p $HOME/$outFolder/assets/junk/ip

	mkdir -p $HOME/$outFolder/content
	mkdir -p $HOME/$outFolder/content/url
	mkdir -p $HOME/$outFolder/content/url/junk
	mkdir -p $HOME/$outFolder/content/spidering
	mkdir -p $HOME/$outFolder/content/params

	mkdir -p $HOME/$outFolder/fuzzing
	mkdir -p $HOME/$outFolder/fuzzing/port
	mkdir -p $HOME/$outFolder/fuzzing/nuclie

	# scope prep
	sed "s/*.//" $1 > $HOME/$outFolder/scope.txt

	# vars
	scope="$HOME/$outFolder/scope.txt"
	
  domain="$HOME/$outFolder/assets/domain.txt"
	ip="$HOME/$outFolder/assets/ip.txt"
  url="$HOME/$outFolder/content/url/url.txt"
	
	assets="$HOME/$outFolder/assets"
	domainJunk="$HOME/$outFolder/assets/junk/domain"
	ipJunk="$HOME/$outFolder/assets/junk/ip"
	
	fuzzing="$HOME/$outFolder/fuzzing"
	portFuzzing="$HOME/$outFolder/fuzzing/port"
  nuclieFuzzing="$HOME/$outFolder/fuzzing/nuclie"
  jaelesFuzzing="$HOME/$outFolder/fuzzing/jaeles"

  content="$HOME/$outFolder/content"
  urlContent="$HOME/$outFolder/content/url"
  urlJunk="$HOME/$outFolder/content/url/junk"
  spideringContent="$HOME/$outFolder/content/spidering"
  paramsContent="$HOME/$outFolder/content/params"

  nucleiTemplates="$HOME/nuclei-templates"
  centNuclei="$HOME/cent-nuclei-templates"
  jaelesSignatures="$HOME/jaeles-signatures"

	# output place
	echo "Output @ ~/$outFolder"

	Subdomain(){
		echo "[+] Subdomains Enumeration"
		# crt.sh
		echo "    Crt.sh"
		while read line
      do curl -s "https://crt.sh/?q=$line&output=json" | jq '.[].name_value' 2>/dev/null | sed 's/\"//g' | sed 's/\*.//g' | sed 's/\\/\n/g' | sort -u >> $domainJunk/crtsh.txt
		done < $scope 

		# assetfinder
		echo "    Assetfinder"
		while read line
      do assetfinder -subs-only $line >> $domainJunk/assetfinder.txt
		done < $scope 

		# subfinder
		echo "    Subfinder"
		subfinder -silent -dL $scope > $domainJunk/subfinder.txt

		# amass enum passive 
		echo "    Amass Passive"
		amass enum -passive -df $scope > $domainJunk/amass_passive.txt

		# Dnsgen
		# active scanning - comment to reduce the time 
		# echo "    Dnsgen"
		# dnsgen -w ./wordlists/dns/subdomains-top1million-20000.txt $scope | httpx -silent > $domainJunk/dnsgen.txt

		# warp all first level subs
		cat $domainJunk/* | sort -u > $domainJunk/domain.txt

		# warp-up all subs
		cat $domainJunk/domain.txt | httpx -silent > $domain
		echo "    Done ... @ ~/$outFolder/assets/domain.txt"
	}

  # gather URLs
  # grep possible vulnerable 
  Url(){
		echo "[+] URL Gathering"
    touch $urlJunk/pureURL.txt
    for i in $(cat $domain); do
      waybackurls $i >> $urlJunk/pureURL.txt
      echo "$i" | gau --subs >> $urlJunk/pureURL.txt
      echo "$i" | hakrawler -subs >> $urlJunk/pureURL.txt
    done
    cat $urlJunk/pureURL.txt | sort -u > $url
    cat $url | qsreplace "FUZZ" > $urlContent/urlFUZZ.txt
    cat $urlContent/urlFUZZ.txt | gf ssrf > $urlContent/urlFUZZssrf.txt  
    cat $urlContent/urlFUZZ.txt | gf sqli > $urlContent/urlFUZZsqli.txt 
    cat $urlContent/urlFUZZ.txt | gf xss > $urlContent/urlFUZZxss.txt 
    cat $urlContent/urlFUZZ.txt | gf lfi > $urlContent/urlFUZZlfi.txt 
    cat $urlContent/urlFUZZ.txt | gf idor > $urlContent/urlFUZZidor.txt 
    cat $urlContent/urlFUZZ.txt | gf redirect > $urlContent/urlFUZZredirect.txt 
    cat $urlContent/urlFUZZ.txt | gf rce > $urlContent/urlFUZZrce.txt 

    # generate wordlist using robots.txt
    
    # cat $url | grep "robots.txt" > $urlJunk/robots.txt
    # while read $i 
    #   do curl -s $i | grep "Disallow" | cut -d " " -f 2 >> $HOME/$outFolder/robots.txt
    # done < $urlJunk/robots.txt
    # rm -rf $urlJunk

  }

  Params(){
    echo "[+] Parameter Collection"
    arjun -T 10 -t 50 -q -i $domain -oB $paramsContent/127.0.0.1:8080 -oT $paramsContent/arjun.txt -w ./wordlists/params.txt 
  }

  # DNS Resolving
	IpResolver(){
		# resolve domain to ip
		massdns -q -r ./wordlists/dns/resolvers.lst -o S -t A -w $ipJunk/massdnsA.txt $domainJunk/domain.txt
		massdns -q -r ./wordlists/dns/resolvers.lst -o S -t TXT -w $ipJunk/massdnsTXT.txt $domainJunk/domain.txt
		grep -ho '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $ipJunk/massdns*.txt | grep -v "0.0.0.0" | sort -u > $ip
	}

  # Spidering
  Spidering(){
    echo "[+] Spidering"
    gospider -S $domain -o $spideringContent -c 10 -t 20 -a -w 1>/dev/null
  }

  # Screenshots
  Screening(){
  	echo "[+] Screening"
    eyewitness -f $domain -d $content/screening 1>/dev/null
  }

  # Vulnerability
  # XSS
  # Xss(){
  #   echo "[+] XSS Testing"
  #   cat $urlContent/urlFUZZ.txt | kxss | grep -P '\[.*?\]' > $vulnerable/xss.txt
  # }

  # SSRF
  # if [ $server ]
  # then
  #   Ssrf(){
  #     echo "[+] SSRF Testing"
  #     cat $urlContent/urlFUZZssrf.txt | qsreplace $server >> $urlContent/urlSERVERssrf.txt
  #     ffuf -w $urlContent/urlSERVERssrf.txt -u FUZZ
  #   }
  # fi
  
  # Port Scanning
  # Brute Spray
  PortScanBruteForceSEQ(){
    echo "[+] Port Scanning"
    rustscan -a $ip -r 1-65535 -b 100 --ulimit 1000 -- -sV -oN $portFuzzing/nmapN.txt -oG $portFuzzing/nmapG.txt 1>/dev/null
		echo "    RustScan Done ... @ ~/$outFolder/fuzzing/port"
    brutespray --file ~/Desktop/nmapG.txt 1>/dev/null
    mv brutespray-output $fuzzing
    echo "    BruteSpray Done ... @ ~/$outFolder/fuzzing/brutespray-output"
    if [ "$(ls -A $fuzzing/brutespray-output)" ]; then
      echo "    Intrsting Files Here"
    else
      echo "    Nothing Interesting"
    fi
  }

  # subdomain TakeOver
  SubdomainTakeOver(){
    echo "[+] SubDomain TakeOver"
    subjack -w $domain -t 100 -timeout $RL -o $fuzzing/subjack.txt -ssl
  }


  # Scanners
  # CVE
  Scanner(){
    echo "[+] Nuclei"
   	nuclei -silent -l $domain -t $centNuclei -o $nuclieFuzzings/nuclie_reports.txt  -me $nuclieFuzzing/nuclie_reports -rl $RL -itoken $server
    echo "[+] Jaeles"
    jaeles scan -s $jaelesSignatures -U $domain -o $jaelesFuzzing -p 'dest=$server' -c $RL 
  }

  clean(){
	  find $HOME/$outFolder -type d -empty -delete -o -type f -empty -delete
  }

	# selection
	read -p "Select path ...
        [1] Subdomain Enumeration & Waybackurls Analysis
        [2] + Vulnerability Scanning
        [3] + Vulnerability Scanning & Port Scanning
        > " choice

	case $choice in
    1)
      Subdomain
      # Screening
      Url
      Spidering
      Params
      clean
      ;;
   
    2)
      Subdomain
      # Screening
      Url
      Spidering
      Params      
      Scanner
      ;;

    3)
      Subdomain
      # Screening
      Url
      Spidering
      Params      
      IpResolver
      PortScanBruteForceSEQ
      Scanner
      ;;
    *)
      echo "Sorry, invalid input"
      ;;
	esac
fi
rm -f resume.cfg geckodriver.log