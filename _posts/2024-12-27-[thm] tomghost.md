## information

![image-20241227191947986](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227191947986.png)

> port scan

![image-20241227191337243](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227191337243.png)

8080端口上是一个tomcat，常规访问下manager，如果能直接上传war就最简单了，但是发现无法通过网页做一个认证，于是我打算使用curl上传war，但是开启了csrf，没法利用。

回过头来看tomcat版本，发现存在一个nday

![image-20241227192046459](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227192046459.png)

> msf

msf可以直接利用，可美了我了，网页上直接显示了账号密码。

## user1

**skyfuck:8730281lkjlkjdqlksalks**

![image-20241227192205901](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227192205901.png)

> skyfuck用户家目录

存在两个文件，下载下来，参考下面这篇文章做一个破解。

https://www.cnblogs.com/jhinjax/p/17058557.html

![image-20241227190459289](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227190459289.png)

>  alexandru

![image-20241227190904179](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227190904179.png)

> 获得密码

## user2

**merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j **

存在suid的zip提权

![image-20241227191050657](../assets/img/2024-12-27-[thm]%20tomghost.assets/image-20241227191050657.png)

> https://gtfobins.github.io/gtfobins/zip/



## conclusion

- 高效的检索可以有效推进
- 挺简单的hah