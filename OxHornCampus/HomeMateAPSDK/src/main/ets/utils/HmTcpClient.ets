import socket from '@ohos.net.socket'
import wifiManager from '@ohos.wifiManager'
import { AegStrUtil } from '@hw-agconnect/petal-aegis'
import { BusinessError } from '@kit.BasicServicesKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer, util, JSON, HashMap } from '@kit.ArkTS';
import HmAPSDKInterface from "./HmAPSDKInterface"

// https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V5/socket-connection-V5#%E5%BA%94%E7%94%A8%E9%80%9A%E8%BF%87-tcp-socket-server-%E8%BF%9B%E8%A1%8C%E6%95%B0%E6%8D%AE%E4%BC%A0%E8%BE%93
let tcp = socket.constructTCPSocketInstance();
let publicKey: string = "khggd54865SNJHGF"

export type tcpCallback = (error?: BusinessError, data?: HashMap <string, string | number> | undefined) => void

class HmTcpClient {
  private callback?: tcpCallback
  private dataView?: Uint8Array
  private receiveDataLength: number = 0

  async connectToDevice(callback?: tcpCallback) {
    this.callback = callback;
    wifiManager.getLinkedInfo().then(data => {
      if (data.ssid == "HomeMate_AP") {
        this.initTCP(callback)
      } else {
        this.didCallback(1, "请连接设备发出的 SSID")
      }
    });
  }

  private async initTCP(callback?: tcpCallback) {
    let state = await tcp.getState();
    if (state.isConnected) {
      if (callback != undefined) {
        callback(undefined);
      }
      return;
    }
    tcp.on("message", value => {
      let buffer = value.message
      this.parseWithData(buffer)
    })
    tcp.on('error', (err: BusinessError) => {
      if (callback != undefined) {
        callback(err);
      }
    });
    tcp.on("connect", () => {
      if (callback != undefined) {
        callback(undefined)
      }
    })
    let ip = wifiManager.getIpInfo().ipAddress;
    let ipString = (ip >> 24 & 0xff) + '.' + (ip >> 16 & 0xff) + '.' + (ip >> 8 & 0xff)
    let address = ipString
    if (ipString.search("172.31.254") != -1) {
      address = "172.31.254.250"
    } else {
      address = ipString + ".1"
    }
    let connectAddress: HmAPSDKInterface.HmTcpAddress = {
      address: address,
      port: 8295,
      family: 1
    }
    tcp.connect({
      address: connectAddress, timeout: 6000
    }, err => {
      if (err) {
        if (callback != undefined) {
          callback(err)
        }
      }
    })
  }

  private crc32(data: Uint8Array): number {
    const table = new Uint32Array(256).map((_, n) => {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      }
      return c >>> 0;
    });
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
      crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  private async parseWithData(originData: ArrayBuffer) {
    let strUtil: AegStrUtil = new AegStrUtil()
    let hdBuffer = originData.slice(0, 2)
    let hdView: Uint8Array = new Uint8Array(hdBuffer)
    let hd: string = strUtil.ohAegUint8ArrayToString(hdView)
    if (hd == "hd") { //新的一包数据
      let lengthBuffer = originData.slice(2, 4);
      const view = new DataView(lengthBuffer);
      let originLength = originData.byteLength;
      let number = view.getInt16(0)
      if (originLength == number) { //说明这个包数据是完整的
        this.dataView = undefined
        this.receiveDataLength = 0
        this.decodeData(originData)
      } else if (originLength < number) { //这一包数据不够，要等下一包数据
        const resultBuffer = new ArrayBuffer(number);
        if (this.dataView == undefined) {
          this.dataView = new Uint8Array(resultBuffer);
        }
        let data = new Uint8Array(originData)
        this.dataView.set(data, 0);
        this.receiveDataLength += originLength
      }
    } else { //不是新的数据，要拆包
      const uint8Array = new Uint8Array(originData); // 将 ArrayBuffer 转为 Uint8Array
      const target = [0x68, 0x64]; // "hd" 的 ASCII 值，十六进制为 0x68 和 0x64
      let index = -1; // 找到目标的起始索引
      // 遍历 Uint8Array
      for (let i = 0; i < uint8Array.length - 1; i++) {
        if (uint8Array[i] === target[0] && uint8Array[i + 1] === target[1]) {
          index = i;
          break;
        }
      }
      if (index !== -1) {
        // 找到了 "hd"，将之前的数据拼接到dataView之后
        let first = originData.slice(0, index);
        let data = new Uint8Array(first)
        if (this.dataView != undefined) {
          this.dataView.set(data, this.receiveDataLength)
        }
        this.receiveDataLength += first.byteLength
        if(this.receiveDataLength == this.dataView?.byteLength) {//说明这一包数据完了,要解析
          this.parseWithData(this.dataView?.buffer.slice(0))
          this.receiveDataLength = 0;
          this.dataView = undefined;
        }
        if (index < originData.byteLength) {//说明，还有剩余的，要重新解析
          let second = originData.slice(index, originData.byteLength);
          this.parseWithData(second);
        }
      } else {//说明没有包头
        let data = new Uint8Array(originData)
        if (this.dataView != undefined) {
          this.dataView.set(data, this.receiveDataLength)
        }
        this.receiveDataLength += originData.byteLength
        if(this.receiveDataLength == this.dataView?.byteLength) {//说明这一包数据完了,要解析
          this.parseWithData(this.dataView?.buffer.slice(0))
          this.receiveDataLength = 0;
          this.dataView = undefined;
        }
      }
    }

  }

  private async decodeData(originData: ArrayBuffer) {
    let originDataView = new DataView(originData)
    let bodyBuffer = originData.slice(42, originDataView.byteLength)
    let msgBodyDecode: Uint8Array = await this.decodeCrypt(publicKey, new Uint8Array(bodyBuffer))
    const decoder = util.TextDecoder.create("utf-8");
    const str = decoder.decodeWithStream(msgBodyDecode);
    try {
      let object: Object | null = JSON.parse(str)
      if (this.callback != undefined) {
        if (object != undefined) {
          let map: Map<string, string | number> = new Map(Object.entries(object));
          let keys = map.keys()
          let hashMap:HashMap<string,string | number> = new HashMap()
          for(let key of keys) {
            hashMap.set(key,map.get(key))
          }
          this.callback(undefined, hashMap);
        } else {
          this.didCallback(2, "解析失败")
        }
      }
    } catch (e) {
      this.didCallback(3, "解析失败")
    }
  }

  private didCallback(code: number, message: string) {
    if (this.callback != undefined) {
      let error: BusinessError = {
        code: code,
        message: message,
        name: "HomeMateAP"
      }
      this.callback(error)
    }
  }

  async sendCmd(msg: HmAPSDKInterface.HmAPCmd, callback?: tcpCallback): Promise<void> {
    this.callback = callback
    let strUtil: AegStrUtil = new AegStrUtil()
    //消息体
    let msgBodyString = JSON.stringify(msg)
    let msgBodyByte = strUtil.ohAegStringToUint8Array(msgBodyString)
    this.sendData(msgBodyByte);
  }

  private async sendData(msgBodyByte: Uint8Array) {
    let strUtil: AegStrUtil = new AegStrUtil()
    //数据头
    let hd = 'hd'
    let hdByte = strUtil.ohAegStringToUint8Array(hd)

    //加密类型
    let type = 'pk'
    let typeByte: Uint8Array = strUtil.ohAegStringToUint8Array(type)

    let key = strUtil.ohAegStringToUint8Array("khggd54865SNJHGF");
    //加密的消息
    let msgBodyEncode: Uint8Array = await this.encrypt(key, msgBodyByte, new Uint8Array());

    //CRC校验
    let crc = this.crc32(msgBodyEncode)
    let sessionId = "kjdbvjdfbkvdsj                  "
    let sessionIdByte = strUtil.ohAegStringToUint8Array(sessionId);
    console.log("sessionIdByte.buffer.byteLength");
    let sessionResult = this.stringToData(sessionIdByte, 32);
    //计算总长度
    let totalLength: number = msgBodyEncode.length + 42

    const resultBuffer = new ArrayBuffer(totalLength);
    const resultView = new Uint8Array(resultBuffer);
    let offset = 0;
    resultView.set(hdByte, offset)
    offset += hdByte.length;
    let length1 = this.numberToUint8ArrayBigEndian(totalLength, 2);
    resultView.set(length1, offset)
    offset += length1.length;
    resultView.set(typeByte, offset)
    offset += typeByte.length
    let crcByte = this.numberToUint8ArrayBigEndian(crc, 4);
    resultView.set(crcByte, offset)
    offset += crcByte.length
    resultView.set(sessionResult, offset)
    offset += sessionResult.length;
    resultView.set(msgBodyEncode, offset)
    let tcpSendOptions: socket.TCPSendOptions = {
      data: resultView.buffer
    }
    tcp.send(tcpSendOptions).then(() => {
      console.log('HomeMate send success')
    }).catch((err: BusinessError) => {
      if (this.callback != undefined) {
        this.callback(err)
      }
    })
  }

  // 字符串转成字节流
  private stringToUint8Array(str: string) {
    return new Uint8Array(buffer.from(str, 'utf-8').buffer);
  }

  private async encrypt(password: Uint8Array, clearText: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    try {
      let generator = cryptoFramework.createSymKeyGenerator("AES128")
      let key = await generator.convertKey({ data: password })
      let paramsSpec: cryptoFramework.IvParamsSpec = { iv: { data: iv }, algName: "IvParamsSpec" }
      let aesCipher = cryptoFramework.createCipher("AES128|ECB|PKCS7")
      await aesCipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, key, paramsSpec)
      let encryptText = await aesCipher.doFinal({ data: clearText })
      return encryptText.data;
    } catch (e) {
      return new Uint8Array()
    }
  }

  private async decodeCrypt(password: string, clearText: Uint8Array): Promise<Uint8Array> {
    try {
      let passwordByte = this.stringToUint8Array(password)
      let generator = cryptoFramework.createSymKeyGenerator("AES128")
      let key = await generator.convertKey({ data: passwordByte })
      let paramsSpec: cryptoFramework.IvParamsSpec = { iv: { data: new Uint8Array() }, algName: "IvParamsSpec" }
      let aesCipher = cryptoFramework.createCipher("AES128|ECB|PKCS7")
      await aesCipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, key, paramsSpec)
      let encryptText = await aesCipher.doFinal({ data: clearText })
      return encryptText.data;
    } catch (e) {
      return new Uint8Array()
    }
  }

  private stringToData(encodedString: Uint8Array, len: number): Uint8Array {
    // 创建一个目标长度的 ArrayBuffer
    const buffer = new ArrayBuffer(len);
    const view = new Uint8Array(buffer);
    // 如果字符串编码后的字节长度超过 len，截断
    if (encodedString.byteLength > len) {
      view.set(encodedString.subarray(0, len));
    } else {
      // 否则，将编码后的字节数据拷贝到 view 中
      view.set(encodedString);
      // 如果字节长度不足 len，则用空格字符 (0x20) 填充
      if (encodedString.length < len) {
        let hexString: string =
          "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
        let byte: ArrayBuffer = this.stringAsciiData(hexString, 112)
        let subByte = byte.slice(0, len - encodedString.length);
        let byteView = new Uint8Array(subByte);
        view.set(byteView, encodedString.length)
      }
    }
    return view
  }

  private stringAsciiData(hexString: string, length: number): ArrayBuffer {
    const bytes = new Uint8Array(length);
    let j = 0;
    for (let i = 0; i < hexString.length; i++) {
      let intCh1: number;
      const hexChar1 = hexString.charAt(i);

      // 处理第一个字符（高位）
      if (hexChar1 >= '0' && hexChar1 <= '9') {
        intCh1 = (parseInt(hexChar1) + 0x00) << 4;
      } else if (hexChar1 >= 'A' && hexChar1 <= 'F') {
        intCh1 = (parseInt(hexChar1, 16) + 0x00) << 4;
      } else {
        intCh1 = (parseInt(hexChar1, 16) + 0x0A) << 4;
      }
      i++;
      if (i >= hexString.length) {
        break;
      }
      let intCh2: number;
      const hexChar2 = hexString.charAt(i);

      // 处理第二个字符（低位）
      if (hexChar2 >= '0' && hexChar2 <= '9') {
        intCh2 = parseInt(hexChar2) + 0x00;
      } else if (hexChar2 >= 'A' && hexChar2 <= 'F') {
        intCh2 = parseInt(hexChar2, 16) + 0x0A;
      } else {
        intCh2 = parseInt(hexChar2, 16) + 0x0A;
      }
      const intCh = intCh1 | intCh2; // 合并高位和低位
      bytes[j] = intCh; // 存储在 bytes 数组中
      j++;
    }
    return bytes.buffer;
  }

  private numberToUint8ArrayBigEndian(value: number, byteLength: number): Uint8Array {
    const result = new Uint8Array(byteLength);
    for (let i = 0; i < byteLength; i++) {
      // 将最高位字节放在结果的最低索引处，依次类推
      result[i] = (value >> (8 * (byteLength - 1 - i))) & 0xFF;
    }
    return result;
  }
}

export default new HmTcpClient();


