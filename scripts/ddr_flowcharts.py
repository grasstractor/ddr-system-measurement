"""RFC verified IP discovery and observed native DoH decision paths.

Generate the bilingual four-lane comparison; R_0 denotes the original DNS IP.
DoT/DoQ appear as distinct alternatives, outside the HTTP nodes.
"""
from pathlib import Path
import hashlib
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.text import Text

from paper_figures import ROOT, NAVY, TEAL, INK, WHITE, configure, txt

NAME='ddr-connection-flows'
FAIL='#79868F'
WIDTH,HEIGHT=7.16,6.50


def content(zh):
    """Reviewed RFC 9462 verified-discovery path and native-client evidence."""
    en=[
      {'heading':['(a) RFC 9462','Verified IP discovery'],
       'protocol':['Select DoH service','Supported ALPN','and SVCB parameters'],
       'address':['Destination address',r'Hints / $T$ Additional',r'or resolve $T$',r'$F$ may differ from $R_0$'],
       'tls':['TLS authentication','Trusted chain',r'$R_0$ in IP SAN','Default certificate','for TLS without SNI'],
       'http':['DoH request','GET / POST',r'authority = $R_0$','Use dohpath'],
       'failure':['Other usable candidate','Else client policy.','Also DDR DoT / DoQ.']},
      {'heading':['(b) Windows 11','DDR enabled'],
       'protocol':['Attempt HTTP/2','h2 or h3 → H2'],
       'address':['Destination address',r'Hints / $T$ Additional',r'A/AAAA; no $T$ lookup',r'$F$ may differ from $R_0$'],
       'tls':['TCP / TLS',r'SNI = $T$','Trusted chain',r'$R_0$ IP SAN + $T$ DNS SAN'],
       'http':['HTTP/2 POST',r'authority = $T$','Use dohpath'],
       'failure':['DDR DoT if usable','Else fallback controls','plaintext / failure.']},
      {'heading':['(c) Android','Auto + DDR enabled'],
       'protocol':['Require h3','Use HTTP/3'],
       'address':['Destination address','Any Additional A/AAAA','else hints; intersect','configured DNS list',r'Single IP: $F=R_0$'],
       'tls':['QUIC / TLS',r'SNI = $T$','Trusted chain',r'$T$ DNS SAN'],
       'http':['HTTP/3 GET',r'authority = $T$','Use dohpath'],
       'failure':['Independent auto DoT',r'at $R_0$:853','Cert./UDP failure → DoT','HTTP 404 → plaintext']},
      {'heading':['(d) macOS','Automatic discovery'],
       'protocol':['Require h2','Use HTTP/2'],
       'address':['Destination address',r'Hint or query $T$ via $R_0$',r'$F$ may differ from $R_0$',r'$T$ NXDOMAIN can','block upgrade'],
       'tls':['TCP / TLS',r'SNI = $T$','Trusted chain',r'$R_0$ IP SAN + $T$ DNS SAN'],
       'http':['HTTP/2 GET',r'authority = $R_0$','Use dohpath'],
       'failure':['DoH preferred to DoT','Single-DoH failure:','plaintext in tests.']},
    ]
    cn=[
      {'heading':['(a) RFC 9462','基于 IP 的验证式发现'],
       'protocol':['选择 DoH 服务','支持宣告的 ALPN','及 SVCB 参数'],
       'address':['确定目标地址',r'hints / $T$ 的 Additional',r'或解析 $T$',r'$F$ 可不同于 $R_0$'],
       'tls':['TLS 身份验证','可信证书链',r'IP SAN 包含 $R_0$','无 SNI 时仍提供','对应证书'],
       'http':['DoH 请求','GET / POST',r'authority = $R_0$','使用 dohpath'],
       'failure':['其他可用候选','否则依客户端策略处理','也支持 DDR DoT / DoQ']},
      {'heading':['(b) Windows 11','已开启 DDR'],
       'protocol':['尝试 HTTP/2','h2 或 h3 → H2'],
       'address':['确定目标地址',r'hints / $T$ 的 Additional',r'A/AAAA；不补查 $T$',r'$F$ 可不同于 $R_0$'],
       'tls':['TCP / TLS',r'SNI = $T$','可信证书链',r'$R_0$ IP SAN + $T$ DNS SAN'],
       'http':['HTTP/2 POST',r'authority = $T$','使用 dohpath'],
       'failure':['可用时选择 DDR DoT','否则由 fallback 控制','使用明文或返回失败']},
      {'heading':['(c) Android','自动模式，已开启 DDR'],
       'protocol':['必须包含 h3','使用 HTTP/3'],
       'address':['确定目标地址','先取任意 Additional','A/AAAA，否则取 hints','与原 DNS 列表求交集',r'单 IP 情形：$F=R_0$'],
       'tls':['QUIC / TLS',r'SNI = $T$','可信证书链',r'$T$ DNS SAN'],
       'http':['HTTP/3 GET',r'authority = $T$','使用 dohpath'],
       'failure':['独立自动 DoT',r'位于 $R_0$:853','证书 / UDP 失败 → DoT','HTTP 404 → 明文']},
      {'heading':['(d) macOS','自动发现'],
       'protocol':['必须包含 h2','使用 HTTP/2'],
       'address':['确定目标地址',r'hint 或经 $R_0$ 查询 $T$',r'$F$ 可不同于 $R_0$',r'$T$ 返回 NXDOMAIN','可阻断升级'],
       'tls':['TCP / TLS',r'SNI = $T$','可信证书链',r'$R_0$ IP SAN + $T$ DNS SAN'],
       'http':['HTTP/2 GET',r'authority = $R_0$','使用 dohpath'],
       'failure':['DoH 优先于 DoT','单一 DoH 失败对照：','测试查询改走明文']},
    ]
    return cn if zh else en


def create(zh=False):
    configure(zh)
    fig=plt.figure(figsize=(WIDTH,HEIGHT))
    ax=fig.add_axes([0,0,1,1]);ax.set_xlim(0,WIDTH);ax.set_ylim(0,HEIGHT);ax.axis('off')
    text_nodes=[]
    def box(x,y,w,h,lines,face=WHITE,edge='#7D8A94',title=True):
        ax.add_patch(Rectangle((x,y),w,h,facecolor=face,edgecolor=edge,lw=.6,zorder=2))
        n=len(lines);spacing=.137 if n<5 else .142
        for i,line in enumerate(lines):
            yy=y+h/2+(n-1)/2*spacing-i*spacing
            t=ax.text(x+w/2,yy,line,ha='center',va='center',fontsize=8.5,
                      fontweight='bold' if title and i==0 else 'normal',color=INK,zorder=3)
            text_nodes.append((t,(x,y,w,h)))
    def arrow(x1,y1,x2,y2,color=NAVY,style='-'):
        ax.annotate('',xy=(x2,y2),xytext=(x1,y1),arrowprops={'arrowstyle':'-|>','lw':.65,'color':color,'linestyle':style,'shrinkA':0,'shrinkB':1.5},zorder=1)
    ax.text(WIDTH/2,6.385,txt(zh,r'$R_0$: original DNS IP     $T$: target name     $F$: encrypted destination IP',r'$R_0$：原 DNS IP     $T$：目标域名     $F$：加密连接的目的 IP'),ha='center',va='center',fontsize=8.5)
    for i,col in enumerate(content(zh)):
        cx=.035+i*1.79;w=1.55;mid=cx+w/2;rail=cx+1.685
        for j,head in enumerate(col['heading']):
            ax.text(mid,6.17-j*.165,head,ha='center',va='center',fontsize=9.0 if j==0 else 8.5,fontweight='bold' if j==0 else 'normal')
        stages=[('protocol',4.82,.49),('address',3.78,.84),('tls',2.72,.86),('http',1.92,.60)]
        previous=5.51
        for key,y,h in stages:
            arrow(mid,previous,mid,y+h)
            box(cx,y,w,h,col[key]);previous=y
            arrow(cx+w,y+h/2,rail,y+h/2,FAIL)
        arrow(mid,previous,mid,1.73)
        box(cx,1.32,w,.41,txt(zh,['HTTP 200','Valid DNS response'],['HTTP 200','有效 DNS 应答']))
        arrow(cx+w,1.525,rail,1.525,FAIL)
        arrow(mid,1.32,mid,1.12)
        box(cx,.84,w,.28,txt(zh,['Use DoH'],['使用 DoH']),face='#EAF4F1',edge=TEAL)
        ax.plot([rail,rail],[5.065,.73],color=FAIL,lw=.65,linestyle=(0,(2.2,1.6)),zorder=1)
        arrow(rail,.73,rail,.68,FAIL)
        ax.text(rail,3.68,txt(zh,'failure','失败'),rotation=90,ha='center',va='center',fontsize=8.5,color=FAIL,bbox={'facecolor':WHITE,'edgecolor':'none','pad':1.0},zorder=4)
        box(cx,.04,1.71,.64,col['failure'],face='#F5F7F8',edge='#AEB8BE')
    # Shared discovery still has one downward branch per client/standard lane.
    box(.035,5.51,7.055,.33,txt(zh,[r'Query $R_0$:53 for _dns.resolver.arpa (SVCB)'],[r'向 $R_0$:53 查询 _dns.resolver.arpa（SVCB）']),title=False)
    fig.canvas.draw();renderer=fig.canvas.get_renderer()
    for t,(x,y,w,h) in text_nodes:
        b=t.get_window_extent(renderer).transformed(ax.transData.inverted())
        assert b.x0>=x+.018 and b.x1<=x+w-.018,(zh,t.get_text(),'horizontal node overflow',b)
        assert b.y0>=y+.015 and b.y1<=y+h-.015,(zh,t.get_text(),'vertical node overflow',b)
    for t in fig.findobj(Text):
        if t.get_visible() and t.get_text():
            b=t.get_window_extent(renderer)
            assert b.x0>=0 and b.y0>=0 and b.x1<=fig.bbox.width and b.y1<=fig.bbox.height,(zh,t.get_text(),'figure overflow')
    folder=ROOT/'zh'/'figures' if zh else ROOT/'figures';folder.mkdir(exist_ok=True)
    fig.savefig(folder/f'{NAME}.pdf',metadata={'Creator':'DDR four-lane flowchart pipeline'})
    fig.savefig(folder/f'{NAME}.png',dpi=240);plt.close(fig)
    mf=folder/'figure-manifest.json';manifest=json.loads(mf.read_text()) if mf.exists() else {'figures':{}}
    f=folder/f'{NAME}.pdf';manifest['figures'][f.name]={'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}
    manifest['vector_pdf_count']=len(list(folder.glob('*.pdf')))
    mf.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(f'Created {f}; all node text fits at 8.5 pt or larger.')


if __name__=='__main__':
    create(False)
    create(True)
