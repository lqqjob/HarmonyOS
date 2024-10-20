//
//  TCPServerController.m
//  HomeMate
//
//  Created by liqiang on 2024/10/16.
//  Copyright © 2024 Air. All rights reserved.
//

#import "TCPServerController.h"
#include <ifaddrs.h>
#include <arpa/inet.h>
#import <CocoaAsyncSocket/GCDAsyncSocket.h>
#import "Gateway+Receive.h"
#import "Gateway+RT.h"
#import "Gateway+HeartBeat.h"
#import "RemoteGateway+RT.h"
#import "Gateway+Send.h"
#import "NSData+AES.h"
#import "NSData+CRC32.h"
#import "SocketSend.h"
#import "HMTaskDistribution.h"
#import "HMVirtualCtrolStatus.h"
#import "HMTransparentCommand.h"
#import <objc/message.h>
@interface TCPServerController ()<GCDAsyncSocketDelegate>
@property (nonatomic, strong) GCDAsyncSocket *serverSocket;   // 服务器端Socket
@property (nonatomic, strong) GCDAsyncSocket *clientSocket;   // 客户端连接的Socket
@end

@implementation TCPServerController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupNavigationBar];
    UILabel * label = [[UILabel alloc] init];
    label.text = [self getIPAddress];
    label.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:label];
    [label mas_makeConstraints:^(MASConstraintMaker *make) {
        make.top.bottom.left.right.mas_equalTo(self.view);
    }];
    
    
    // 初始化服务器端Socket
       self.serverSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:dispatch_get_main_queue()];
       
       // 开启监听端口
       NSError *error = nil;
       if ([self.serverSocket acceptOnPort:10002 error:&error]) {
           NSLog(@"Server is listening on port 10002");
       } else {
           NSLog(@"Error starting server: %@", error);
       }
    
}


-(void)setupNavigationBar
{
    self.view.backgroundColor = kHMV2BackgroundColor;
    
    NSString *title = @"TCPServer";
    
    NSDictionary *dic = [[NSDictionary alloc] initWithObjects:@[title,@"nav_ios_back",@"system_monitoring_record"] forKeys:@[Navi_Title,Navi_LeftImgNormal,Navi_RightImgNormal]];
    [self customizeNaviBarForDictionary:dic barType:navi_LeftBtn_RightBtn];
    
    [self setNavBarStyleToV2];
}
- (NSString *)getIPAddress {
    NSString *address = @"error";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    
    // Retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while (temp_addr != NULL) {
            if (temp_addr->ifa_addr->sa_family == AF_INET) {
                // Check if interface is en0 (Wi-Fi)
                if ([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    // Get the IP address
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs(interfaces);
    return address;
}

// 当客户端连接时调用
- (void)socket:(GCDAsyncSocket *)sock didAcceptNewSocket:(GCDAsyncSocket *)newSocket {
    NSLog(@"New client connected: %@", newSocket.connectedHost);
    
    // 保存客户端的 socket
    self.clientSocket = newSocket;
   
    // 读取数据
    [self.clientSocket readDataWithTimeout:-1 tag:0];
}

// 读取客户端数据
- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    NSString *message = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"Received data: %@", message);
  

    [self didReceiveData:data];
    // 回应客户端，表示数据已收到
    NSString *response = @"Data received!";
    [self.clientSocket writeData:[response dataUsingEncoding:NSUTF8StringEncoding] withTimeout:-1 tag:0];
    
    // 继续监听客户端发来的数据
    [self.clientSocket readDataWithTimeout:-1 tag:0];
}

// 处理Socket断开连接
- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
    NSLog(@"Client disconnected: %@", sock.connectedHost);
}

- (BOOL)didReceiveData:(NSData *)data
{
    //LogFuncName();
    NSDictionary *payloadDic = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingAllowFragments error:nil];

    NSUInteger length = data.length;

    if (length > 42)
    {
        NSData *ptData = [data subdataWithRange:NSMakeRange(4, 2)];
        NSString *protocolType = [[NSString alloc]initWithData:ptData encoding:NSASCIIStringEncoding];
        
        NSData *crcData = [data subdataWithRange:NSMakeRange(6, 4)];
        NSUInteger receive_crc = getCrcValue(crcData);
        
        NSData * payLoadData = [data subdataWithRange:NSMakeRange(42, length - 42)];
//        id payLoadData1 = [[NSString alloc]initWithData:payLoadData encoding:NSASCIIStringEncoding];
//        NSData * payLoadDataEncode = [payLoadData hm_AES128EncryptWithHexKey:PUBLICAEC128KEY iv:nil];
        NSDictionary *payloadDic = [NSJSONSerialization JSONObjectWithData:payLoadData options:NSJSONReadingAllowFragments error:nil];
        NSUInteger check_crc = [payLoadData hm_crc32];
        
        if (receive_crc == check_crc) {
            
            
            NSString *key =  PUBLICAEC128KEY;
            
            NSData * decrytedpayLoadData = [payLoadData hm_AES128DecryptWithKey:PUBLICAEC128KEY iv:nil];
            if (!decrytedpayLoadData) { // 尝试公钥解密
                decrytedpayLoadData = [payLoadData hm_AES128DecryptWithKey:PUBLICAEC128KEY iv:nil];
            }
            
            if (decrytedpayLoadData)
            {
                NSError * error = nil;
                NSDictionary *payloadDic = [NSJSONSerialization JSONObjectWithData:decrytedpayLoadData options:NSJSONReadingAllowFragments error:&error];
                id payLoadData1 = [[NSString alloc]initWithData:decrytedpayLoadData encoding:NSASCIIStringEncoding];

                if (error) {
                    NSString * decryptionString  = [[NSString alloc] initWithData:decrytedpayLoadData encoding:NSUTF8StringEncoding];
                    NSData *head = [data subdataWithRange:NSMakeRange(0, 2)];
                    NSString *headString = [[NSString alloc]initWithData:head encoding:NSASCIIStringEncoding];

                    DLog(@"接收数据解析失败，错误 error = %@，\n 失败的字符串 = %@ \n headString = %@ \n protocolType = %@ \n [data protocolLength] = %d \n check_crc = %d",[error description],decryptionString,headString,protocolType,[data hm_protocolLength],check_crc);

                    if (decryptionString) {
                        
                        DLog(@"接收数据内容:%@",decryptionString);
                        
                        decryptionString = [decryptionString stringByReplacingOccurrencesOfString : @"\r\n" withString : @"" ];
                        decryptionString = [decryptionString stringByReplacingOccurrencesOfString : @"\n" withString : @"" ];
                        decryptionString = [decryptionString stringByReplacingOccurrencesOfString : @"\t" withString : @"" ];
                        
                        DLog(@"修正后的字符串：%@",decryptionString);
                        
                        NSError * error = nil;
                        NSData *correctionData = [decryptionString dataUsingEncoding:NSUTF8StringEncoding];
                        payloadDic = [NSJSONSerialization JSONObjectWithData:correctionData options:NSJSONReadingAllowFragments error:&error];
                        if (error) {
                            DLog(@"字符串校正后仍然解析失败，错误 error = %@",[error description]);
                            
                            DLog(@"Head = %@ Len = %d ProtocolType = %@ CRC = %d SessionId = %@ 头部信息:%@",asiiStringWithData([data subdataWithRange:NSMakeRange(0, 2)]),[data hm_protocolLength],protocolType,receive_crc,asiiStringWithData([data subdataWithRange:NSMakeRange(10, 32)]),[data subdataWithRange:NSMakeRange(0, 42)]);
                        }
                    }else{
                        
                        DLog(@"----------数据异常 无法转换为UTF8字符串----------");
                        
                        DLog(@"Head = %@ Len = %d ProtocolType = %@ CRC = %d SessionId = %@ 头部信息:%@",asiiStringWithData([data subdataWithRange:NSMakeRange(0, 2)]),[data hm_protocolLength],protocolType,receive_crc,asiiStringWithData([data subdataWithRange:NSMakeRange(10, 32)]),[data subdataWithRange:NSMakeRange(0, 42)]);
                    }
                    
                }
                
                if (payloadDic) {
                    // 接收到当前播放什么音乐的socket结果
                    DLog(@"接收数据Payload",payloadDic);
                    
                }else {
                    
                    int lenNum = [data hm_protocolLength];
                    int length = (int)data.length;
                    
                    DLog(@"----------数据异常 实际长度:%d 协议长度:%d----------",length,lenNum);
         
                }
            }else {
                DLog(@"----------数据异常 解密失败:\n%@----------",decrytedpayLoadData);
                

            }
            
        }else {
            
            DLog(@"----------数据异常 crc 校验失败\n----------");

        }
        
    }else {
        DLog(@"----------数据异常 长度小于42----------");
    }

    
    return YES;
}


/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
