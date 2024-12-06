@Builder
export function SetWiFiAndPasswordBuilder(name: string, param: Object) {
  SetWiFiAndPassword()
}

@Component
export struct SetWiFiAndPassword {
  pageInfos: NavPathStack = new NavPathStack()
  private mac: string = ""
  @State private ssid: string = ""

  build() {
    NavDestination() {
      Text(this.ssid)
        .fontSize(16)
        .fontColor(Color.Black)
        .width("100%")
        .height("40")
    }

    .title("设置 WiFi 名称和密码")
    .onReady((context: NavDestinationContext) => {
      this.pageInfos = context.pathStack
      let params = this.pageInfos.getParamByName("SetWiFiAndPassword") as string[]
      this.mac = params[0]
      this.ssid = params[1]
    })
  }
}