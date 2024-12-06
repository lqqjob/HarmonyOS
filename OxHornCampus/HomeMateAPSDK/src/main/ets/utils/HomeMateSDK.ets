import TcpClient, { tcpCallback } from "./HmTcpClient"
import HmAPSDKInterface from "./HmAPSDKInterface"

class HomeMateSDK {
  connect(callback?: tcpCallback) {
    TcpClient.connectToDevice((e) => {
      if (e == undefined) {
        this.getDeviceInfo((e, data) => {


        })
      }
      if(callback !== undefined) {
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

  getWiFiList(callback?:tcpCallback) {
    let wifiCmd:HmAPSDKInterface.HmAPCmd = {
      cmd:80
    }
    TcpClient.sendCmd(wifiCmd,callback)
  }

  setWiFi(ssid:string,password?:string,callback?:tcpCallback) {
    let setWiFiCmd:HmAPSDKInterface.HmAPSetWiFiCmd = {
      cmd:80,
      ssid:ssid,
      password:password
    }
    TcpClient.sendCmd(setWiFiCmd,callback)
  }
}

export default new HomeMateSDK();