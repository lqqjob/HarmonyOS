import socket from '@ohos.net.socket'
import wifiManager from '@ohos.wifiManager'
import { AegStrUtil} from '@hw-agconnect/petal-aegis'
import { BusinessError} from '@kit.BasicServicesKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer } from '@kit.ArkTS';

// https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V5/socket-connection-V5#%E5%BA%94%E7%94%A8%E9%80%9A%E8%BF%87-tcp-socket-server-%E8%BF%9B%E8%A1%8C%E6%95%B0%E6%8D%AE%E4%BC%A0%E8%BE%93
let tcp = socket.constructTCPSocketInstance();
 let publicKey:string = "khggd54865SNJHGF"


interface GeneratedObjectLiteralInterface_1 {
  address: string;
  port: number;
  family: number;
}

interface APMessageBody {
  source: string;
  serial: number;
  uniSerial: number;
  softwareVersion: string;
  clientType: number;
  ver: string;
  language: string;
  cmd: number;
  sysVersion: string;
  hardwareVersion: string;
}


export default async function initTcp() {
  let state = await tcp.getState();
  if (state.isConnected) {
    let params: APMessageBody = {
      source: "ZhiJia365",
      serial: 244555721,
      uniSerial: 1724917244555,
      softwareVersion: "5.1.1.402",
      clientType: 2,
      ver: "5.1.1.402",
      language: "zh",
      cmd: 0,
      sysVersion: "iOS 17.5.1",
      hardwareVersion: "iPhone 12",
    }
    sendTest(params)
    return;
  }


  tcp.on("message", value => {
    console.log('HomeMate getRemoteAddressfail');
    let buffer = value.message
    decoderWithData(buffer)
  })
  tcp.on('error', (err: BusinessError) => {
    console.log("on error, err:" + JSON.stringify(err))
    console.log("on error, err:" + JSON.stringify(err))
  });
  tcp.on("connect", () => {
    let params: APMessageBody = {
      source: "ZhiJia365",
      serial: 244555721,
      uniSerial: 1724917244555,
      softwareVersion: "5.1.1.402",
      clientType: 2,
      ver: "5.1.1.402",
      language: "zh",
      cmd: 0,
      sysVersion: "iOS 17.5.1",
      hardwareVersion: "iPhone 12",
    }
    sendTest(params)
  })
  let ip = wifiManager.getIpInfo().ipAddress;
  let ipString = (ip >> 24 & 0xff) + '.' + (ip >> 16 & 0xff) + '.' + (ip >> 8 & 0xff)
  let address = ipString
  if (ipString.search("172.31.254") != -1) {
    address = "172.31.254.250"
  } else {
    address = ipString + ".1"
  }
  let connectAddress: GeneratedObjectLiteralInterface_1 = {
    address:address,
    port: 8295,
    family: 1
  };

  tcp.connect({
    address: connectAddress, timeout: 6000
  }, err => {
    if (err) {
      console.log('HomeMate connect fail');
      return;
    }
    tcp.getRemoteAddress((err: BusinessError, data: socket.NetAddress) => {
      if (err) {
        console.log('HomeMate getRemoteAddressfail');
        return;
      }
      console.log('HomeMate getRemoteAddresssuccess:' + JSON.stringify(data));
    })
  })


}

async function decoderWithData(originData: ArrayBuffer): Promise<string>  {
  let strUtil: AegStrUtil = new AegStrUtil()
  let originDataView = new DataView(originData)
  let hdBuffer = originData.slice(0, 2)
  let hdView: Uint8Array = new Uint8Array(hdBuffer)
  let hd: string = strUtil.ohAegUint8ArrayToString(hdView)
  let bodyBuffer = originData.slice(42, originDataView.byteLength)
  let msgBodyDecode: Uint8Array = await decodeCrypt(publicKey,new Uint8Array(bodyBuffer))
  let msgBodyString:string = strUtil.ohAegUint8ArrayToString(msgBodyDecode)

  return msgBodyString

}
async function sendTest(msg: APMessageBody): Promise<void> {
  let strUtil: AegStrUtil = new AegStrUtil()
  //数据头
  let hd = 'hd'
  let hdByte = strUtil.ohAegStringToUint8Array(hd)

  //加密类型
  let type = 'pk'
  let typeByte: Uint8Array = strUtil.ohAegStringToUint8Array(type)

  //消息体
  let msgBodyString = JSON.stringify(msg)
  let msgBodyByte= strUtil.ohAegStringToUint8Array(msgBodyString)
  let key = strUtil.ohAegStringToUint8Array("khggd54865SNJHGF");
  //加密的消息
  let msgBodyEncode: Uint8Array = await encrypt(key,msgBodyByte,new Uint8Array());

  //CRC校验
  let crc = crc32(msgBodyEncode)
  let sessionId = "kjdbvjdfbkvdsj                  "
  let sessionIdByte = strUtil.ohAegStringToUint8Array(sessionId);
  console.log("sessionIdByte.buffer.byteLength");
  let sessionResult = stringToData(sessionIdByte, 32);
  //计算总长度
  let totalLength: number = msgBodyEncode.length + 42

  const resultBuffer = new ArrayBuffer(totalLength);
  const resultView = new Uint8Array(resultBuffer);
  let offset = 0;
  resultView.set(hdByte, offset)
  offset += hdByte.length;
  let length1 = numberToUint8ArrayBigEndian(totalLength, 2);
  resultView.set(length1, offset)
  offset += length1.length;
  resultView.set(typeByte, offset)
  offset += typeByte.length
  let crcByte = numberToUint8ArrayBigEndian(crc, 4);
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
    console.log('HomeMate send fail')
  })

}
// 字符串转成字节流
function stringToUint8Array(str: string) {
  return new Uint8Array(buffer.from(str, 'utf-8').buffer);
}
async function encrypt(password: Uint8Array, clearText: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
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
async function decodeCrypt(password: string, clearText: Uint8Array): Promise<Uint8Array> {
  try {
    let passwordByte = stringToUint8Array(password)
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
function stringToData(encodedString: Uint8Array, len: number): Uint8Array {

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
      let byte: ArrayBuffer = stringAsciiData(hexString, 112)
      let subByte = byte.slice(0, len - encodedString.length);
      let byteView = new Uint8Array(subByte);
      view.set(byteView, encodedString.length)
    }
  }

  return view
}

function stringAsciiData(hexString: string, length: number): ArrayBuffer {
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


function numberToUint8ArrayBigEndian(value: number, byteLength: number): Uint8Array {
  const result = new Uint8Array(byteLength);

  for (let i = 0; i < byteLength; i++) {
    // 将最高位字节放在结果的最低索引处，依次类推
    result[i] = (value >> (8 * (byteLength - 1 - i))) & 0xFF;
  }
  return result;
}

function crc32(data: Uint8Array): number {
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


