declare namespace HmAPSDKInterface {

  interface HmAPCmd {
    cmd:number
  }

  interface HmAPSetWiFiCmd extends HmAPCmd {
    ssid:string,
    password?:string
  }

  interface HmTcpAddress {
    address: string;
    port: number;
    family: number;
  }
  interface HmDeviceInfo {
    deviceName: string;
    uid: string;
  }
}

 export default HmAPSDKInterface
