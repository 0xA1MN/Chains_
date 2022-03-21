#!/bin/bash
# TODO: js and analysis -> https://github.com/nahamsec/JSParser & https://github.com/GerbenJavado/LinkFinder
# TODO: selection 
# TODO: coloring
# TODO: obsidian - generate using this script

## cat xxxxxxxxx.com/assets/domain.txt | cut -d / -f 3
## for i in `cat ~/xxxxxxxxx.com/assets/domain.txt | cut -d / -f 3`; do touch $i.md; done
# loop -> create - screen - headers - toggle with response "mark down report"


cat <<"EOF"

    ____ _           _           
   / ___| |__   __ _(_)_ __  ___ 
  | |   | '_ \ / _\ | | '_ \/ __|
  | |___| | | | (_| | | | | \__ \
   \____|_| |_|\__,_|_|_| |_|___/
				0xA1MN
  Automae Recon Process Using Awesome Tools.
  Twitter: https://twitter.com/0xA1MN 


EOF


# check inputs
if [ -z "$1" ] && [ -z "$2" ]; then
	echo "Invalid Format ./chains.sh [scope.txt] [OutFolder]"
	echo ""
    exit
else
    export outFolder=$2
    export server=$3
    export RL=50 # scanners rate limit

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
	mkdir -p $HOME/$outFolder/content/js

	mkdir -p $HOME/$outFolder/fuzzing
	mkdir -p $HOME/$outFolder/fuzzing/port
	mkdir -p $HOME/$outFolder/fuzzing/nuclie

    mkdir -p $HOME/$outFolder/Report

	# scope prep
	sed "s/*.//" $1 > $HOME/$outFolder/scope.txt

	# vars
	export scope="$HOME/$outFolder/scope.txt"
    export BGPID=""
	# main
    export domain="$HOME/$outFolder/assets/domain.txt"
    export domainLive="$HOME/$outFolder/assets/domain_live.txt"
	export ip="$HOME/$outFolder/assets/ip.txt"
    export urlUniq="$HOME/$outFolder/content/url/urlUniq.txt"
    export urlUro="$HOME/$outFolder/content/url/urlUro.txt"
	# assets folder
	export assets="$HOME/$outFolder/assets"
	export assetsJunkDomain="$HOME/$outFolder/assets/junk/domain"
	export assetsJunkIp="$HOME/$outFolder/assets/junk/ip"
	# fuzzing folder
	export fuzzing="$HOME/$outFolder/fuzzing"
	export fuzzingPort="$HOME/$outFolder/fuzzing/port"
    export fuzzingNuclie="$HOME/$outFolder/fuzzing/nuclie"
    export fuzzingJaeles="$HOME/$outFolder/fuzzing/jaeles"
    # content folder
    export content="$HOME/$outFolder/content"
    export contentUrl="$HOME/$outFolder/content/url"
    export contentUrlJunk="$HOME/$outFolder/content/url/junk"
    export contentSpidering="$HOME/$outFolder/content/spidering"
    export contentParams="$HOME/$outFolder/content/params"
    # Report Folder
    export report="$HOME/$outFolder/Report"
    # scanners templates folder
    export nucleiTemplates="$HOME/nuclei-templates"
    export centNuclei="$HOME/cent-nuclei-templates"
    export jaelesSignatures="$HOME/jaeles-signatures"

	# output place
	echo "Output @ ~/$outFolder"

	Subdomain(){
		echo "[+] Subdomains Enumeration"
		# crt.sh
		echo "    Crt.sh"
		while read line
            do curl -s "https://crt.sh/?q=$line&output=json" | jq '.[].name_value' 2>/dev/null | sed 's/\"//g' | sed 's/\*.//g' | sed 's/\\/\n/g' | sort -u >> $assetsJunkDomain/crtsh.txt
		done < $scope 
		# assetfinder
		echo "    Assetfinder"
		while read line
            do assetfinder -subs-only $line >> $assetsJunkDomain/assetfinder.txt
		done < $scope 
		# subfinder
		echo "    Subfinder"
		subfinder -silent -dL $scope > $assetsJunkDomain/subfinder.txt
		# amass enum passive 
		echo "    Amass Passive"
		amass enum -passive -df $scope > $assetsJunkDomain/amass_passive.txt
		# Gobuster vHost
        echo "    Gobuster vHost"
        for i in cat $scope
            do gobuster vhost -q -u $i -w ./wordlists/dns/subdomains-top1million-20000.txt | cut -d " " -f 2 > $assetsJunkDomain/gobuster_vhost.txt&
            BGPID="$BGPID $!"
        done
	}


    # gather URLs
    # grep possible vulnerable 
    Url(){
		echo "[+] URL Gathering"
        touch $contentUrlJunk/pureURL.txt
        for i in $(cat $domainLive); do
            waybackurls $i >> $contentUrlJunk/pureURL.txt
            echo "$i" | gau --subs >> $contentUrlJunk/pureURL.txt
            echo "$i" | hakrawler -subs >> $contentUrlJunk/pureURL.txt
        done
		echo "    Further Processing"
        sort -u $contentUrlJunk/pureURL.txt > $urlUniq
        cat $urlUniq | uro | sort -u > $contentUrl/urlUro.txt # uro: declutters url lists for crawling/pentesting
        cat $urlUro | qsreplace "FUZZ" > $contentUrl/urlFUZZ.txt
        cat $contentUrl/urlFUZZ.txt | gf ssrf > $contentUrl/urlFUZZssrf.txt  
        cat $contentUrl/urlFUZZ.txt | gf sqli > $contentUrl/urlFUZZsqli.txt 
        cat $contentUrl/urlFUZZ.txt | gf xss > $contentUrl/urlFUZZxss.txt 
        cat $contentUrl/urlFUZZ.txt | gf idor > $contentUrl/urlFUZZidor.txt 
        cat $contentUrl/urlFUZZ.txt | gf redirect > $contentUrl/urlFUZZredirect.txt 
        cat $contentUrl/urlFUZZ.txt | gf rce > $contentUrl/urlFUZZrce.txt 
        cat $contentUrl/urlFUZZ.txt | gf lfi > $contentUrl/urlFUZZlfi.txt
        
        # xss
        # for i in `cat /tmp/tmp`; do curl -s $i | grep "\<img src=x onerror=alert(1);\>" && echo "VULN: $i";done

        # extract params 
		echo "    Extract Params & Subs"
        cat $urlUro | unfurl --unique keys > $contentParams/paramsURL.txt
        # extract subs push them to assets junk domain folder
        cat $urlUniq | unfurl --unique domains > $assetsJunkDomain/domainURL.txt
        # create wordlist from url
		echo "    Create Custom Wordlist"
        cat $urlUniq | unfurl --unique paths | sed -r 's#/#\n#g' | sort -u > $content/wordlist_URL.txt
		
        echo "    Collect Useful Endpoints"
        grep ".js$" $urlUniq > $content/jsURL.txt
        grep ".php$" $urlUniq > $content/phpURL.txt
        grep ".aspx$" $urlUniq > $content/aspxURL.txt
        grep ".jsp$" $urlUniq > $content/jspURL.txt
    }


    ProcessDomains(){
        # wait vhost fuzzing
        wait $BGPID
        # proccess domains
        cp $HOME/$outFolder/scope.txt $assetsJunkDomain/scope.txt # add scope to attack surface
		# warp all domians
        cat $assetsJunkDomain/* | sort -u > $assetsJunkDomain/all.txt

        # Verfiy in scope domains 
        for i in `cat $scope`
            do grep "\.$i\|^$i" $assetsJunkDomain/all.txt >> $domain
        done

		# check live ones
		httpx -silent -l $domain > $domainLive
		echo "    Domains Done ... @ ~/$outFolder/assets"
    }            


    Params(){
        echo "[+] Parameter Collection"
        arjun -T 10 -t 10 -q -i $domainLive -m GET -oT $contentParams/params_GET -w ./wordlists/params.txt >/dev/null&
        BGPID="$BGPID $!"
        arjun -T 10 -t 10 -q -i $domainLive -m POST -oT $contentParams/params_POST -w ./wordlists/params.txt >/dev/null&
        BGPID="$BGPID $!"
        arjun -T 10 -t 10 -q -i $domainLive -m JSON -oT $contentParams/params_JSON -w ./wordlists/params.txt >/dev/null&
        BGPID="$BGPID $!"
        arjun -T 10 -t 10 -q -i $domainLive -m XML -oT $contentParams/params_XML -w ./wordlists/params.txt >/dev/null&
        BGPID="$BGPID $!"
    }

    # DNS Resolving
	IpResolver(){
		# resolve domain to ip
		massdns -q -r ./wordlists/dns/resolvers.lst -o S -t A -w $assetsJunkIp/massdnsA.txt $domain
		massdns -q -r ./wordlists/dns/resolvers.lst -o S -t TXT -w $assetsJunkIp/massdnsTXT.txt $domain
		grep -ho '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $assetsJunkIp/massdns*.txt | grep -v "0.0.0.0" | sort -u > $ip
	}

    # Spidering
    Spidering(){
        echo "[+] Spidering"
        gospider -S $domainLive -o $contentSpidering -c 10 -t 20 -a -w 1>/dev/null
        # TODO: handle spidering output
    }

    # Screenshots
    Screening(){
        echo "[+] Screening"
        eyewitness -f $domain -d $content/screening 1>/dev/null
    }

    # Port Scanning
    # Brute Spray
    PortScanBruteForceSEQ(){
        echo "[+] Port Scanning"
        rustscan -a $ip -r 1-65535 -b 100 --ulimit 1000 -- -sV -oN $fuzzingPort/nmapN.txt -oG $fuzzingPort/nmapG.txt 1>/dev/null
            echo "    RustScan Done ... @ ~/$outFolder/fuzzing/port"
        brutespray --file ~/Desktop/nmapG.txt > /dev/null
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
        nuclei -silent -l $domainLive -t $centNuclei -o $fuzzingsNuclie/nuclie_reports.txt  -me $fuzzingNuclie/nuclie_reports -rl $RL #-itoken $server
        echo "[+] Jaeles"
        jaeles scan -s $jaelesSignatures -U $domainLive -o $fuzzingJaeles -c $RL # -p 'dest=$server' 
    }

    # delete emapty files and directories
    clean(){
        find $HOME/$outFolder -type d -empty -delete -o -type f -empty -delete
        rm -rf $HOME/$outFolder/content/url/junk $HOME/$outFolder/assets/junk/domain
        rm -f resume.cfg geckodriver.log
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
        ProcessDomains
        Spidering
        Params
        echo "[+] Wait Background Processes: $BGPID"
        wait $BGPID
        clean
        ;;
   
    2)
        Subdomain
        # Screening
        Url
        ProcessDomains
        Spidering
        Params      
        Scanner
        echo "[+] Wait Background Processes: $BGPID"
        wait $BGPID
        clean
        ;;

    3)
        Subdomain
        # Screening
        Url
        ProcessDomains
        Spidering
        Params      
        IpResolver
        PortScanBruteForceSEQ
        Scanner
        echo "[+] Wait Background Processes: $BGPID"
        wait $BGPID
        clean
        ;;
    *)
        echo "Sorry, invalid input"
        ;;
	esac
fi
