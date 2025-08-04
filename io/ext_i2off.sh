#!/bin/bash
#sh ext_i2off.sh $dev $inodenum [hexdump lenth]
#
#eg:
#
#check file: inode 26815
#root@VM-68-100-ubuntu:~# ./ext_i2off.sh /dev/vda1 26815

dev=$1
[[ ! -n $dev ]] && echo "no dev" && exit 1
inode=$2
[[ ! -n $inode ]] && echo "no inode" && exit 1
lenth=$3
[[ ! -n $lenth ]] && lenth=128

bsize=`dumpe2fs $dev 2>/dev/null |head -n 50|grep "Block size"|awk '{print $NF}' `
inoden=`dumpe2fs $dev 2>/dev/null|head -n 50|grep "Inodes per group"|awk '{print $NF}' `
isize=`dumpe2fs $dev 2>/dev/null |head -n 50|grep "Inode size"|awk '{print $NF}' `
echo "Block size $bsize"
echo "Inodes per group $inoden"
echo "Inode size $isize"
ngroup=`echo "scale=0; $inode / $inoden" | bc`
ininode=`echo "scale=0; $inode % $inoden "| bc`
tableoff=`dumpe2fs $dev 2>/dev/null|grep "Group ${ngroup}:" -A 5|grep "Inode table at"|awk -F '-' '{print $1}'|awk '{print $NF}'`
echo "inode $inode in group $ngroup, inode $ininode, table offset $tableoff"
offinode=`echo "scale=0; ($ininode-1) * $isize + $tableoff * $bsize" | bc`
echo "dev inode $offinode"
iblock=`echo $offinode + 40|bc`
data=`hexdump $dev -C -n 8 -s $iblock`
extend=`echo $data|grep "0a f3"`
if [ ! -n "$extend" ];then
    b16=`echo "$data"|awk '{for(i=0;i<=NF-1;i++)printf("%s ",$(NF-i));printf("\n");}'|awk '{print $6 $7 $8 $9}'`
else
    echo "EXT4 extend tree"
    hexdump $dev -C -n 64 -s $offinode
    iblock=`echo $offinode + 60|bc`
    b16=`hexdump $dev -C -n 4 -s $iblock|awk '{print $5 $4 $3 $2}'`
    echo $b16
fi
b10=`echo $((0x$b16))`
entryoff=`echo "$b10 * $bsize"|bc`
echo "offset block $entryoff"
echo "hexdump $dev -C -n $lenth -s $entryoff"
hexdump $dev -C -n $lenth -s $entryoff
