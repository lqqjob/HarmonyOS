import TcpClient, { tcpCallback } from "./HmTcpClient"
import HmAPSDKInterface from "./HmAPSDKInterface"
import { http } from '@kit.NetworkKit';
import { BusinessError, systemDateTime } from '@kit.BasicServicesKit';
import { buffer, HashMap, util } from '@kit.ArkTS';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';

class HomeMateSDK {
  connect(callback?: tcpCallback) {
    TcpClient.connectToDevice((e) => {
      if (callback !== undefined) {
        callback(e)
      }
    });
  }

  getDeviceInfo(callback?: tcpCallback) {
    let deviceInfoCmd: HmAPSDKInterface.HmAPCmd = {
      cmd: 79
    }
    TcpClient.sendCmd(deviceInfoCmd, callback);
  }

  getWiFiList(callback?: tcpCallback) {
    let wifiCmd: HmAPSDKInterface.HmAPCmd = {
      cmd: 80
    }
    TcpClient.sendCmd(wifiCmd, callback)
  }

  setWiFi(ssid: string, password?: string, callback?: tcpCallback) {
    let setWiFiCmd: HmAPSDKInterface.HmAPSetWiFiCmd = {
      cmd: 81,
      ssid: ssid,
      password: password
    }
    if (password === undefined || password.length == 0) {
      setWiFiCmd = {
        cmd: 81,
        ssid: ssid,
      }
    }
    TcpClient.sendCmd(setWiFiCmd, callback)
  }

  checkOnlineForMac(mac: string, callback?: tcpCallback) {
    let httpRequest = http.createHttp()
    httpRequest.request("https://homemate.orvibo.com/getDeviceOnlineStatus?uid=" + mac,
      (error: Error, data: http.HttpResponse) => {
        if (error !== undefined) {
          this.callbackError(error.message, callback)
        } else {
          let map: HashMap<string, string | number> = new HashMap();
          let result = data.result as string;
          let object: object | null = JSON.parse(result)
          if (object != undefined) {
            let tempMap: Map<string, string | number> = new Map(Object.entries(object));
            let online = tempMap.get("online")
            map.set("online", online)
            if (callback !== undefined) {
              callback(undefined, map)
            }
          } else {
            this.callbackError("解析结果失败", callback)
          }
        }
      })
  }

  async bindDeviceWithMac(mac: string, appId: string, appKey: string, token: string, callback?: tcpCallback) {
    let number = systemDateTime.getTime();
    let time = Math.floor(number / 1000)
    let requestId = this.generateRandomString(32)
    let version = 2
    let namespace: string = "Device.Bind"
    let originString = namespace + requestId + version.toString() + token + time.toString() + appKey
    let sign = await this.sha1String(originString)
    let params: HashMap<string, number | string | HashMap<string, number | string>> = new HashMap()
    params.set("namespace", namespace)
    params.set("requestId", requestId)
    params.set("version", 2)
    params.set("accessToken", token)
    params.set("uid", mac)

    let signInfo: HashMap<string, number | string> = new HashMap()
    signInfo.set("time", time)
    signInfo.set("appId", appId)
    signInfo.set("sign", sign)

    params.set("signInfo", signInfo)

    let string = JSON.stringify(params)

    let httpRequest = http.createHttp();
    let options: http.HttpRequestOptions = {
      method: http.RequestMethod.POST, // 可选，默认为http.RequestMethod.GET
      // 当使用POST请求时此字段用于传递请求体内容，具体格式与服务端协商确定
      extraData: string,
      expectDataType: http.HttpDataType.OBJECT, // 可选，指定返回数据的类型
      usingCache: false, // 可选，默认为true
      priority: 1, // 可选，默认为1
      header: { 'content-type': 'application/json' },
      readTimeout: 60000, // 可选，默认为60000ms
      connectTimeout: 60000, // 可选，默认为60000ms
      usingProtocol: http.HttpProtocol.HTTP1_1, // 可选，协议类型默认值由系统自动指定
      usingProxy: false, //可选，默认不使用网络代理，自API 10开始支持该属性
    };
    httpRequest.request("https://open-api.orvibo.com/smart-home365", options, (err: Error, data: http.HttpResponse) => {
      if (!err) {
        let result = data.result as object;
        let map: Map<string, string | number> = new Map(Object.entries(result));
        let keys = map.keys()
        let hashMap: HashMap<string, string | number> = new HashMap()
        for (let key of keys) {
          hashMap.set(key, map.get(key))
        }
        if(callback !== undefined) {
          callback(undefined,hashMap)
        }
        console.info('Result:' + data.result);
        console.info('code:' + data.responseCode);
        console.info('type:' + JSON.stringify(data.resultType));
        console.info('header:' + JSON.stringify(data.header));
        console.info('cookies:' + data.cookies); // 自API version 8开始支持cookie
      } else {
        this.callbackError(err.message,callback);
      }
    });
  }

  private async sha1String(originString: string) {
    let md = cryptoFramework.createMd('SHA1');
    await md.update({ data: new Uint8Array(buffer.from(originString, 'utf-8').buffer) });
    let mdOutput = await md.digest();
    const decoder = util.TextDecoder.create("utf-8");
    const str = decoder.decodeWithStream(mdOutput.data);
    return str;

  }

  private generateRandomString(count: number) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < count; i++) {
      result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result.toLowerCase();
  }

  private callbackError(message: string, callback?: tcpCallback) {
    if (callback !== undefined) {
      let e: BusinessError = {
        code: 1,
        message: message,
        name: "HomeMateAP"
      }
      callback(e)
    }
  }
}

export default new HomeMateSDK();