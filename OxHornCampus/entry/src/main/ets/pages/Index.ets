import { router } from '@kit.ArkUI';
import { BusinessError } from '@kit.BasicServicesKit';
import initTcp from './TcpClient';

@Entry
@Component
struct Index {
  @State message: string = 'Hello World';

  build() {
   Row() {
     Column() {
       Text(this.message)
         .fontSize(50)
         .fontWeight(FontWeight.Bold)
       Button() {
         Text('Next')
           .fontSize(30)
           .fontWeight(FontWeight.Bold)
       }
       .type(ButtonType.Capsule)
       .margin({top:20})
       .backgroundColor('#0dffb')
       .width('40%')
       .height('5%')
       .onClick(()=>{
         initTcp();
         // router.pushUrl({url:'pages/Second'})
         //   .then(()=>{
         //     console.info('Succeed in jumping to the second page')
         //   }).catch((error:BusinessError)=>{
         //   console.error(`Failed to jump to the second page.Code is ${error.code}, message is ${error.message}`)
         // })
       })
     }
     .width('100%')
   }
    .height('100%')
  }
}