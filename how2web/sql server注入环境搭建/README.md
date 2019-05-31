> 环境：win7+iis+sql server
>
> 网页脚本：asp

&emsp;&emsp;<font size=2>这篇主要是记录一下我为了搭建《sql注入攻击与防御 第2版》这本书漏洞环境的过程，当然是最简单的过程，那么就先从Windows平台的sql server开始吧。</font></br>

&emsp;&emsp;<font size=2>首先你要安装sql server，我这里安装的是sql server 2008，准备如下两个安装包（都可以在微软官网上下载到）：</font></br>

![]()

&emsp;&emsp;<font size=2>其中一个sql server 2008的安装包，还有一个是sql server manager studio，如果只安装了前者的话你可能会不知道怎么连接到sql server。这两个安装的过程比较简单，稍作讲解就行了，在这里要全选</font></br>

![]()

&emsp;&emsp;<font size=2>然后服务器配置里这样选就可以了：</font></br>

![]()

&emsp;&emsp;<font size=2>数据库引擎配置可以选择混合模式，然后自己设置一个密码，并添加当前用户进管理员：</font></br>

![]()

&emsp;&emsp;<font size=2>然后下一步到安装完成就行了，sql server manager studio就不需要解释了，这个安装比较简单，接下来就是一个比较大的坑了，就是启动了sql server manager studio后怎么连的问题，首先先打开sql server配置管理器，确保sql server（SQLEXPRESS）正确运行：</font></br>

![]()

&emsp;&emsp;<font size=2>然后确保sql server网络配置下的sqlexpress协议下的这三个项都是启用的：</font></br>

![]()

&emsp;&emsp;<font size=2>然后双机tcp/ip进入属性，在ipall栏里清空动态端口，然后设置tcp端口为1433（不改虽然sql server manager studio能连，但是后续asp脚本不方便连接）：</font></br>

![]()

&emsp;&emsp;<font size=2>然后我们就可以进入sql server manager studio进行最后的一些配置了，打开后先选择Windows身份验证：</font></br>

![]()

&emsp;&emsp;<font size=2>点击连接就进去了，然后我们创建一个sql server账号用来给asp连接，左侧展开**安全性->登录名->新建登录名**：</font></br>

![]()

&emsp;&emsp;<font size=2>然后在这里选择**sql server身份验证**，然后**设置一下自己的密码**（强制密码策略和密码过期可以自己看着选，这个没啥好说的），设置**默认数据库**为自己要连的数据库（没有的可以先创建），然后在**服务器角色**里出于方便可以直接选sysadmin，然后选择好自己数据库的映射，在下方**数据库角色**中选择db_owner：</font></br>

![]()

![]()

&emsp;&emsp;<font size=2>然后退出登录，重新选择就可以用自己新建的账号连接sql server了，然后我们讲解一下iis的配置，首先在控制面板处点击程序->打开或关闭Windows功能，勾选**Internet信息服务**下的**Web管理工具**和**万维网服务**（全都要），如下图：</font></br>

![]()

&emsp;&emsp;<font size=2>完了之后点击确定等待开启就行了，然后重新进入控制面板，搜索打开**管理工具**，**双击iis管理器**（不是6.0，是下面那个）->**双击asp**->**展开调试属性**->**开启错误发送到浏览器**：</font></br>

![]()

&emsp;&emsp;<font size=2>如果想自由设置一下自己的网站根目录的话，可以在左侧资源栏里**展开网站**->**右键default web site**->**管理网站**->**高级设置**，然后就不用我说了吧：</font></br>

![]()

&emsp;&emsp;<font size=2>最后我们在default web site主页里**双击默认文档**->**添加一个index.asp并移到最上方**，这是为了方便:</font></br>

![]()

&emsp;&emsp;<font size=2>这下网站相关的配置终于搞完了，接下来在网站的根目录（一般来说都是C:\inetpub\wwwroot\）下创建一个index.asp文件：</font></br>

```asp
<%

dim conn 
set conn = server.createobject("adodb.connection") 
conn.Open "Provider=SQLOLEDB;Data Source=127.0.0.1,1433;User ID=fanda;Password=root;Initial Catalog=newsdb"

dim rs,sql 
set rs = server.createobject("adodb.recordset") 

dim id
id=Request.QueryString("id")

sql = "select * from news where id="+id 
rs.open sql,conn,1,1 

while not rs.EOF
%>
    <tr>
        <td><%=rs("id")%></td>
        <td><%=rs("title")%></td>
        <td><%=rs("author")%></td>
    </tr>
    
<%
    rs.MoveNext
wend

%>
```

&emsp;&emsp;<font size=2>在这里对这些参数进行一些解释：</font></br>

- Provider：sql协议，在这里SQLOLEDB就是MSSQL协议了，用这个就好；
- Data Source：[ip address],[port]。也就是说在这里我用了127.0.0.1的地址（本机地址）和1433端口（之前设置的sql server端口）；
- User ID和Password：这个很简单，顾名思义，你创建的用户的账号密码；
- Initial Catalog：你要连接的数据库

&emsp;&emsp;<font size=2>在这里我的脚本非常简单，取出url后的参数作为id进入数据库查询，非常明显的sql注入漏洞，然后下面的html标签就是打印了数据库中的字段。最终效果如下：</font></br>

![]()