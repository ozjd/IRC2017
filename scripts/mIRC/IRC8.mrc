; MSN Chat IRCX(8) compatibility for mIRC - by JD.
; Requires mIRC v7.46
;
; Current: mIRC v $+ $version

;Todo - Hash table MSN profile info
;Todo - Decode MSN Style Text Chat - CTCP STYLE
;Todo - Passport Updater

on 1:LOAD:{ var %i 1, %x ; | while ($true) { %x = $read($script,%i) | if ($left(%x,1) !== ;) break | echo $color(info2) -st $iif($eval($right(%x,-1)),$v1,-) | inc %i } }
on 1:START:{ jd.update | .timerjd.update 0 3600 jd.update }

on ^1:LOGON:*:{ if ($version > 7.44) { raw -qn IRCVERS IRC8 MSN-OCX!9.02.0310.2401 $iif(%locale,$v1,EN-US) | raw -qn AUTH GateKeeper $+ $iif(%PassportTicket,Passport) I $+(:GKSSP\0JD,$chr(3),\0\0\0,$chr(1),\0\0\0) | haltdef } }
on *:PARSELINE:*:*:{
  if ($parsetype === in) {
    tokenize 32 $parseline
    if ($2 === 004) .parseline -itq $1 005 $3 PREFIX=(qov).@+ CHANTYPES=%# CHANLIMIT=%:1
    ;<- :TK2CHATCHATA01 306 JD :You have been marked as being away
    ;<- :TK2CHATCHATA01 305 JD :You are no longer marked as being away
    elseif ($2 === 353) { var %i = 1, %r, %t, %u, %v = $right($6-,-1) | while (%i <= $numtok(%v,32)) { %t = $gettok(%v, %i, 32) | %u = $gettok(%t, 4, 44) | %r = %r %u | .parseline -itqp : $+ $remove(%u,.,@,+) MSNPROFILEDATA $5 %t | inc %i } | .parseline -it $1-5 : $+ %r }
    ;<- :JD!9B792D0F1E1E2714@GateKeeperPassport 822 :Reason
    ;<- :JD!9B792D0F1E1E2714@GateKeeperPassport 821 :User unaway    
    elseif (AUTH GateKeeper* iswm $1-2) { if ($3 === S) { if ($4 == :OK) { raw -qn $1-3 $+(:,$base($len(%PassportTicket),10,16,8),%PassportTicket,$base($len(%PassportProfile),10,16,8),%PassportProfile)) } | else { | if ((!%GUID) || ($remove(%GUID,0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F) !== $null) || ($len(%GUID) != 32)) set %GUID $eval($str($ $+ base($ $+ r(0,15),10,16) $ $+ + $chr(32),32) $+ $ $+ chr(32),2) | bset -a &challenge 1 $gettok($regsubex($4 $+ $servertarget,/(\\?.)/gu,$iif(\* iswm \1,$replacex(\1,\ $+ 0,0,\ $+ t,9,\ $+ n,10,\ $+ r,13,\ $+ b,32,\ $+ c,44,\ $+ \,92),$asc(\1)) $+ $chr(32)),18-,32) | raw -qn $1-3 $+(:GKSSP\0JD,$chr(3),\0\0\0,$chr(3),\0\0\0,$regsubex($hmac(&challenge,SRFMKSJANDRESKKC,md5,1) $+ $iif($2 === GateKeeperPassport,$str(0,32),$+($mid(%GUID,7,2),$mid(%GUID,5,2),$mid(%GUID,3,2),$left(%GUID,2),$right(%GUID,24))),/([0-9A-Fa-f]{2})/g,$iif(\1 isin 00 0A 0D 2C 09 5C 20,\ $+ $replacex(\1,00,0,0A,n,0D,r,2C,c,09,t,5C,\,20,b),$chr($base(\1,16,10))))) } } | else { if (*Passport iswm $2) { if (%MSNREGCookie) raw -q PROP $ MSNREGCOOKIE : $+ $v1 | else { raw -q USER  mIRC * * :mIRC $version (Win $+ $os $+ ) | raw -q NICK $me } | raw -q PROP $ MSNProfile : $+ $iif(%MSNProfile,$v1,0) } | else raw -q NICK > $+ $me | if (%UserRole) raw -q PROP $ ROLE : $+ $v1 | if ((*Passport iswm $2) && (%SubscriberInfo)) raw -q PROP $ SUBSCRIBERINFO : $+ $v1 } | .parseline -it }
    elseif ($2 === JOIN) { var %t = $right($gettok($1,1,33),-1) | .parseline -it $1-2 $4- | .parseline -itqp : $+ %t MSNPROFILEDATA $right($4,-1) $3 | if ($gettok($3,4,44) !== $null) .parseline -itq : $+ $server MODE $right($4,-1) + $+ $replace($v1,.,q,@,o,+,v) $str(%t $+ $chr(32),$len($v1)) }
    elseif ($2 === MSNPROFILEDATA) {
      ; Add to hash table. (we must remember these)
      ; Check away/return (4 raws)
      ; Bonus: Check prop MSNPROFILE
      var %a cline -m, %b $3 $utfdecode($right($1,-1)), %r
      tokenize 44 $4-
      if ($2 === U) {
        if (G* iswm $3) %r = 3
        elseif (M* iswm $3) %r = 12
        elseif (F* iswm $3) %r = 13
        else %r = $color(Listbox Text)
      }
      else %r = $color(Title Text)
      if ($1 === G) %r = $color(Gray Text)
      %a %r %b
      .parseline -it
    }
    elseif ($2 === PROP) { if (($4 === OWNERKEY) || ($4 === HOSTKEY)) { var %s = $+($server,$chr(44),$3,$chr(44),$4), %k = $right($5,-1), %a = irc7.ini keys %s %k | if (%k) writeini %a | elseif ($readini(irc7.ini,keys,%s)) remini %a } }
  }
  else { var %d | tokenize 32 $left($parseline,-1) | if (($1- === PASS) && ($chr(37) $+ #* iswm $active)) { .parseline -ot | raw -q MODE $me +h $$?="Please enter the host keyword" } | elseif ($1 === JOIN) { var %i = 1, %r, %s, %c | while (%i <= $numtok($2,44)) { %c = $iif(%i !== 1,$chr(44)) | %d = $gettok($2,%i,44) | %r = $+(%r,%c,%d) | %s = $+(%s,%c,$iif($readini(irc7.ini,keys,$+($server,$chr(44),%d,$chr(44),OWNERKEY)), $v1,$iif($readini(irc7.ini,keys,$+($server,$chr(44),%d,$chr(44),HOSTKEY)), $v1, $gettok($3,%i,44)))) | inc %i } | .parseline -otn $1 %r %s } }
}

; Self updater. Remove if you don't want this script to automatically update itself.
alias jd.update { sockclose jd.update | var %d = jd.update cdn.rawgit.com | sockopen $iif($sslready, -e %d 443, %d 80) | echo $color(info) -st * Checking for automatic updates... }
on 1:sockopen:jd.update:{ if ($sockerr > 0) { echo $color(info) -st * Automatic update failed (Connection error) | return } | write -c $qt($scriptdirtmp.bin) | sockwrite $sockname GET /ozjd/IRC2017/master/scripts/mIRC/IRC8.mrc HTTP/1.0 $+ $crlf | sockwrite $sockname HOST: cdn.rawgit.com $+ $crlf $+ $crlf }
on 1:sockread:jd.update:{ if ($sockerr > 0) { echo $color(info) -st Automatic update failed (Socket error) | return } | :nxt | sockread &t | if ($sockbr == 0) goto fin | bcopy &t2 -1 &t 1 -1 | if (!$sock($sockname).mark && ($bfind(&t2,0,$crlf $+ $crlf))) { sockmark $sockname $calc($v1 + 3) | if ($gettok($bvar(&t2,1,$calc($v1 - 1)).text,2,32) !== 200) { echo $color(info) -st * Automatic update failed (HTTP Status != 200) | sockclose $sockname | return } } | goto nxt | :fin | if ($sock($sockname).mark > -1) { bcopy &t3 1 &t2 $calc($v1 + 1) $calc($bvar(&t2,0) - $v1) | bwrite $qt($scriptdirtmp.bin) -1 -1 &t3 | sockmark $sockname 0 } | else { echo $color(info) -st * Automatic update failed (Parsing error) | sockclose $sockname } }
on 1:sockclose:jd.update:{ if ($sockerr > 0) echo $color(info) -st * Automatic update failed (Premature disconnect) | else { if ($md5($scriptdirtmp.bin,2) === $md5($script,2)) echo $color(info) * No new updates found | else { echo $color(info) * New update successfully installed! | .rename -fo $qt($scriptdirtmp.bin) $qt($script) | .load -rs1 $qt($script) } } }

