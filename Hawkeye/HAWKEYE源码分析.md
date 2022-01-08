# HAWKEYE源码分析

是前后端的github的监控平台  

搭建的时候有点问题 主要是 mongodb的问题  
用 3.x+版本还是不行会报错  

这里把他的连接mongodb的地方修改下  
修改成如下 将mongodb uri加上用户名密码  
还有 `/server/health.py` 下的对应修改

`/server/config/database.py`  

```python
if os.environ.get('MONGODB_URI'):
    MONGODB_URI = os.environ.get('MONGODB_URI')
else:
    if os.environ.get('MONGODB_USER'):
        MONGODB_USER = os.environ.get('MONGODB_USER')
        MONGODB_PASSWORD = os.environ.get('MONGODB_PASSWORD')
        MONGODB_URI = 'mongodb://{0}:{1}@localhost:27017'.format(MONGODB_USER, MONGODB_PASSWORD)
    else:
        MONGODB_URI = 'mongodb://localhost:27017'
client = MongoClient(MONGODB_URI, connect=False)
db = client.get_database('hawkeye')
```


mongodb容器启动  

`sudo docker run -d -p 27017:27017 --name mongodb -e MONGO_INITDB_ROOT_USERNAME=用户名 -e MONGO_INITDB_ROOT_PASSWORD=密码 -v $PWD/db:/data/db mongo`    

将当前路径下的db挂载到 容器的 /data/db 即mongo存储的数据  

这样就可以了启动了  
我看github上别人提交的issue 都提到这个地方也没人回复. 这里我就不提交上去了   

启动后 还是有个问题 没有登录验证界面的  

![首頁](/images/首頁.jpg)  

这里可以使用 启动的时候 设置端口的时候 -p 127.0.0.1:8087:80 的方式将端口限制到本机  
然后再通过nginx 转发到本机 这个时候添加上 登录验证 需要nginx 配置个server  
这种方式是个方案 暂时没有尝试不确定可行性  

## 源码分析
client 是vue写的前端 打包出来的在 `client/dist` 下 构建镜像的时候也是ADD 到镜像  
server是后端 flask写的  
deploy 是一些配置文件  nginx supervisor等  

我们这里主要查看下后端代码  

config 下是 `databases.py` 是数据库相关的 通过环境变量获取 mongodb的相关数据  

后端使用 restful风格 使用的是`Flask-RESTful`库来搞的  

`controllers/statistic.py`  
是 首页数据盘的处理  

`controllers/result.py`  
是 获取数据的处理  

`controllers/health.py`  
是获取 github接口和mongodb状态的健康状态获取  


`controllers/setting.py`  
是设置一些参数的处理  

`utils` 下是一些公共方法 还有对邮件的操作  

`api.py` 是对之前控制器下的restful处理的注册下  

`task.py`  

是基于 huey 的异步任务队列  

基于redis的 跟celery很像 直接将普通函数修改为异步函数
huey提供了huey_consumer.py  
`huey_consumer.py task.huey -k process -w 4`  
这条命令也可以在 supervisor配置看到  

```shell
-w n                 worker的数量
-k process/thread/greenlet    worker使用线程还是进程还是greenlet
-v           log输出详细的debug信息
```

从github抓取的话  

```python
repos = g.search_code(query=query.get('keyword'),
                        sort="indexed", order="desc")
```

还有邮件  

`@huey.periodic_task` 是周期性任务的  

`@huey.periodic_task(crontab(minute='*/2'))` 

这样可以在 huey官方文档看到  
这样是定期任务 每三分钟执行一次  

```python
@huey.periodic_task(crontab(minute='*/3'))
def every_three_minutes():
    print('This task runs every three minutes')
```
官方文档地址 : https://huey.readthedocs.io/en/latest/  

剩下主要就是核心的就是搜索规律了  



























