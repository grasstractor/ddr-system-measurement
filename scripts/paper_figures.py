"""Bilingual conference-paper figures from immutable experiment summaries."""
from pathlib import Path
import hashlib, itertools, json, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager
import numpy as np
from matplotlib.lines import Line2D
from matplotlib.patches import Rectangle
from matplotlib.ticker import FixedLocator, FixedFormatter, NullLocator
from matplotlib.transforms import blended_transform_factory

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data'
NAVY,TEAL,GOLD,INK,MUTED,PALE,GRID,WHITE='#273F57','#007F78','#B16B29','#202A33','#59656E','#F3F5F6','#DFE4E8','#FFFFFF'
PROFILES=['windows','android','macos'];NAMES=['Windows','Android','macOS']

def load(name):return json.loads((DATA/name).read_text(encoding='utf-8'))
def txt(zh,en,cn):return cn if zh else en

def select_font(zh):
    """Choose an installed publication font on Windows, macOS, or Linux."""
    installed={font.name for font in font_manager.fontManager.ttflist}
    candidates=(['Microsoft YaHei','Noto Sans CJK SC','Noto Sans SC',
                 'Source Han Sans SC','PingFang SC','Heiti SC','WenQuanYi Zen Hei']
                if zh else ['Arial','DejaVu Sans'])
    for name in candidates:
        if name in installed:
            return name
    raise RuntimeError('Chinese figures need a CJK font. Install Noto Sans CJK SC '
                       'or another font listed in docs/FIGURES.md, then rerun.')

def configure(zh):
    plt.rcParams.update({'font.family':[select_font(zh),'DejaVu Sans'],'font.size':8.5,
      'axes.labelsize':8.5,'axes.titlesize':9.5,'xtick.labelsize':8.5,'ytick.labelsize':8.5,
      'text.color':INK,'axes.labelcolor':INK,'axes.edgecolor':'#7D8992','xtick.color':INK,'ytick.color':INK,
      'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':.5,'grid.color':GRID,'grid.linewidth':.45,
      'axes.axisbelow':True,'pdf.fonttype':42,'ps.fonttype':42,'axes.unicode_minus':False,
      'savefig.facecolor':WHITE,'figure.facecolor':WHITE,'legend.frameon':False,'lines.solid_capstyle':'butt',
      'xtick.major.width':.5,'ytick.major.width':.5,'xtick.major.size':2.5,'ytick.major.size':2.5})

def save(fig,folder,name):
    folder.mkdir(parents=True,exist_ok=True)
    fig.savefig(folder/f'{name}.pdf',metadata={'Creator':'DDR reproducible figure pipeline'})
    fig.savefig(folder/f'{name}.png',dpi=240)
    plt.close(fig)

def clean(ax):
    for sp in ax.spines.values():sp.set_visible(False)
    ax.tick_params(length=0)

def methodology(folder,zh,e):
    fig,ax=plt.subplots(figsize=(7.16,1.93));fig.subplots_adjust(left=.004,right=.996,bottom=.02,top=.98)
    ax.set_xlim(0,7.1);ax.set_ylim(0,1.88);ax.axis('off')
    def block(x,y,w,h,heading,lines):
        ax.add_patch(Rectangle((x,y),w,h,facecolor=WHITE,edgecolor='#697681',lw=.65))
        ax.text(x+.09,y+h-.085,heading,fontsize=9,fontweight='bold',va='top')
        ax.text(x+.09,y+.09,lines,fontsize=8.5,va='bottom',linespacing=1.25)
    block(.03,1.05,1.79,.7,txt(zh,'Native client controls','系统原生对照'),txt(zh,'Windows / Android / macOS\nDiscovery, TLS, HTTP, recovery','Windows / Android / macOS\n发现、TLS、HTTP、故障恢复'))
    block(.03,.12,1.79,.7,txt(zh,'Public DNS discovery','公网 DNS 发现'),txt(zh,'IPv4 scan + IPv6 Hitlist\nSingapore and Los Angeles','IPv4 扫描 + IPv6 Hitlist\n新加坡与洛杉矶'))
    block(2.24,.48,2.14,.91,txt(zh,'Executable client profiles','可执行客户端模型'),txt(zh,'Qualifying SVCB advertisements\nTLS/QUIC → HTTP → DNS\nAddress-level outcomes','有效 SVCB 宣告\nTLS/QUIC → HTTP → DNS\n逐地址记录结果'))
    block(4.83,1.04,2.23,.72,txt(zh,'Rule comparison','系统规则对比'),txt(zh,'Individual + combined changes\nCross-site success-set comparison','单项与组合规则变化\n跨测点比较成功集合'))
    block(4.83,.1,2.23,.75,txt(zh,'Functional comparison','解析功能比较'),txt(zh,'Paired plaintext/encrypted queries\nNative policy change and restoration','明文 / 加密查询配对\n原生策略改变与恢复'))
    for y in [1.40,.47]:
        ax.plot([1.82,2.02,2.02],[y,y,.93],color='#697681',lw=.6)
    ax.annotate('',xy=(2.24,.93),xytext=(2.02,.93),arrowprops={'arrowstyle':'-|>','lw':.65,'color':INK})
    ax.plot([4.38,4.59,4.59],[.93,.93,1.4],color='#697681',lw=.6)
    ax.plot([4.59,4.59],[.475,.93],color='#697681',lw=.6)
    for y in [1.4,.475]:ax.annotate('',xy=(4.83,y),xytext=(4.59,y),arrowprops={'arrowstyle':'-|>','lw':.65,'color':INK})
    save(fig,folder,'methodology')

def overlap(folder,zh,sets):
    union=set.union(*sets.values());groups=[]
    for bits in itertools.product([False,True],repeat=3):
        if not any(bits):continue
        result=union.copy()
        for p,on in zip(PROFILES,bits):result=result&sets[p] if on else result-sets[p]
        groups.append((bits,len(result)))
    groups.sort(key=lambda x:x[1],reverse=True)
    fig=plt.figure(figsize=(3.5,2.38));gs=fig.add_gridspec(2,1,height_ratios=[2.25,1],hspace=.08,left=.28,right=.985,top=.97,bottom=.07)
    ax=fig.add_subplot(gs[0]);mat=fig.add_subplot(gs[1],sharex=ax)
    xs=np.arange(7);vals=[n for _,n in groups];colors=[TEAL if all(b) else NAVY for b,_ in groups]
    ax.bar(xs,vals,color=colors,width=.63,zorder=3)
    for x,v in zip(xs,vals):ax.text(x,v+1,str(v),ha='center',fontsize=8.5)
    ax.set_ylabel(txt(zh,'Intersection size','交集地址数'));ax.set_ylim(0,53);ax.set_yticks([0,20,40]);ax.grid(axis='y')
    ax.tick_params(axis='x',bottom=False,labelbottom=False);ax.spines['bottom'].set_visible(False)
    for y in [0,2]:mat.axhspan(y-.42,y+.42,color=PALE,zorder=0)
    for x,(bits,n) in enumerate(groups):
        ys=[2-i for i,b in enumerate(bits) if b]
        if len(ys)>1:mat.plot([x,x],[min(ys),max(ys)],color=colors[x],lw=1.1)
        for i,b in enumerate(bits):mat.scatter(x,2-i,s=20,color=colors[x] if b else '#D7DEE2',zorder=3)
    mat.set_yticks([2,1,0],[f'{n} ({len(sets[p])})' for p,n in zip(PROFILES,NAMES)],fontsize=8.5)
    mat.set_xticks([]);mat.set_ylim(-.55,2.55);mat.tick_params(axis='y',length=0,pad=5)
    for sp in mat.spines.values():sp.set_visible(False)
    save(fig,folder,'success-overlap');return groups

def failure_stages(folder,zh,totals):
    fig,ax=plt.subplots(figsize=(3.5,2.20));fig.subplots_adjust(left=.235,right=.835,top=.73,bottom=.22)
    labs=txt(zh,['Address selection','Service / protocol','Original-IP SAN','Other failures'],['地址选择','服务 / 协议','原 IP SAN','其他失败'])
    colors=[NAVY,'#97A8B6',GOLD,'#D4DADF',TEAL]
    for y,p in enumerate(PROFILES):
        v=totals[p];vals=[v['discovery_ineligible'],v['no_compatible_service'],v['missing_original_ip_san'],sum(v[k] for k in ['connect_or_handshake_failure','certificate_chain_failure','target_name_mismatch','http_or_dns_failure']),v['pass']];left=0
        for i,n in enumerate(vals):
            pct=n/348769*100;ax.barh(y,pct,left=left,color=colors[i],height=.57,edgecolor=WHITE,linewidth=.25,label=labs[i] if i<4 and y==0 else None)
            if pct>18:ax.text(left+pct/2,y,f'{pct:.1f}%',ha='center',va='center',color=WHITE if i in [0,2] else INK,fontsize=8.5)
            left+=pct
        ax.text(1.215,y,str(v['pass']),transform=ax.get_yaxis_transform(),ha='right',va='center',fontsize=8.5,color=TEAL)
    ax.text(1.215,-.79,txt(zh,'Pass','成功'),transform=ax.get_yaxis_transform(),ha='right',va='center',fontsize=8.5,color=TEAL)
    ax.set_yticks(range(3),NAMES);ax.invert_yaxis();ax.set_xlim(0,100);ax.set_xticks([0,50,100]);ax.set_ylim(2.52,-.56)
    ax.set_xlabel(txt(zh,'Share of resolver addresses (%)','占原 DNS 地址的比例（%）'),labelpad=4)
    ax.tick_params(axis='y',length=0,pad=5);ax.spines['left'].set_visible(False)
    fig.legend(*ax.get_legend_handles_labels(),loc='upper left',bbox_to_anchor=(.015,.995),ncol=2,fontsize=8.5,handlelength=1,columnspacing=1.0,labelspacing=.5)
    save(fig,folder,'failure-stages')

def interventions(folder,zh,e):
    variants=[['baseline','R1','R5','R1+R5'],['baseline','R2','R3','R6','R2+R3','R2+R6','R3+R6','R2+R3+R6'],['baseline','R4','R5','R4+R5']]
    fig=plt.figure(figsize=(7.16,4.08));ax=fig.add_axes([.29,.12,.415,.785])
    trans=blended_transform_factory(fig.transFigure,ax.transData)
    y=0
    for pi,(p,name,vv) in enumerate(zip(PROFILES,NAMES,variants)):
        if pi:ax.axhline(y-.62,color='#89949C',lw=.45,xmin=-.65,xmax=1.67,clip_on=False)
        ax.text(.018,y,name,transform=trans,fontsize=9,fontweight='bold',va='center')
        for var in vv:
            d=e['rules']['comparison'][p+'/'+var];s,l=d['singapore'],d['los_angeles']
            ax.axhline(y,color=GRID,lw=.35,zorder=0)
            ax.plot([s,l],[y,y],color=MUTED,lw=.65,zorder=2)
            ax.scatter(s,y-.115,marker='o',s=13,c=NAVY,zorder=4)
            ax.scatter(l,y+.115,marker='D',s=14,facecolors=WHITE,edgecolors=TEAL,linewidths=.9,zorder=4)
            ax.text(.145,y,txt(zh,'Baseline','基线') if var=='baseline' else var,transform=trans,fontsize=8.5,va='center')
            ax.text(.84,y,f'{s:,}',transform=trans,ha='right',va='center',fontsize=8.5)
            ax.text(.985,y,f'{l:,}',transform=trans,ha='right',va='center',fontsize=8.5)
            y+=1
        y+=.55
    ax.set_xscale('log');ax.set_xlim(40,500000);ax.set_ylim(y-1.05,-.65)
    ax.xaxis.set_major_locator(FixedLocator([100,1000,10000,100000]));ax.xaxis.set_major_formatter(FixedFormatter(['100','1,000','10,000','100,000']));ax.xaxis.set_minor_locator(NullLocator())
    ax.set_yticks([]);ax.spines['left'].set_visible(False);ax.grid(axis='x',lw=.4);ax.set_xlabel(txt(zh,'Successful resolver addresses (log scale)','成功的原 DNS 地址数（对数坐标）'),labelpad=5)
    for x,label,ha in [(.018,txt(zh,'Profile','模型'),'left'),(.145,txt(zh,'Rule','规则'),'left'),(.84,txt(zh,'Singapore','新加坡'),'right'),(.985,txt(zh,'Los Angeles','洛杉矶'),'right')]:
        fig.text(x,.951,label,ha=ha,fontsize=8.5,fontweight='bold')
    handles=[Line2D([0],[0],marker='o',ls='none',color=NAVY,markersize=3.5,label='SG'),Line2D([0],[0],marker='D',ls='none',markerfacecolor=WHITE,markeredgecolor=TEAL,markersize=3.5,label='LA')]
    ax.legend(handles=handles,loc='lower center',bbox_to_anchor=(.5,1.028),ncol=2,fontsize=8.5,handletextpad=.4,columnspacing=1.2,borderaxespad=0)
    save(fig,folder,'rule-interventions')

def interactions(folder,zh,e):
    fig,axs=plt.subplots(1,2,figsize=(7.16,2.03));fig.subplots_adjust(left=.10,right=.972,bottom=.23,top=.73,wspace=.40)
    specs=[('windows','R1','R1+R5',txt(zh,'(a) Windows: add target lookup','(a) Windows：增加目标查询')),
           ('macos','R4','R4+R5',txt(zh,'(b) macOS: use authority T','(b) macOS：使用 authority T'))]
    for ax,(p,r,combo,head) in zip(axs,specs):
        for si,site in enumerate(['singapore','los_angeles']):
            cmp=e['rules']['comparison'];vals=[cmp[p+'/'+r][site]-cmp[p+'/baseline'][site],cmp[p+'/'+combo][site]-cmp[p+'/R5'][site]]
            yy=np.arange(2)+(si-.5)*.33;col=[NAVY,TEAL][si]
            ax.barh(yy,vals,height=.29,color=col,zorder=3)
            for y,n in zip(yy,vals):
                ax.text(n-2600 if n>10000 else n+3200,y,f'+{n:,}',ha='right' if n>10000 else 'left',va='center',color=WHITE if n>10000 else INK,fontsize=8.5)
        ax.set_yticks([0,1],txt(zh,['IP SAN\nkept','IP SAN\nremoved'],['保留\nIP SAN','移除\nIP SAN']),fontsize=8.5);ax.invert_yaxis();ax.set_ylim(1.48,-.48)
        ax.set_xlim(0,160000);ax.set_xticks([0,50000,100000,150000],['0','50k','100k','150k']);ax.grid(axis='x')
        ax.tick_params(axis='y',length=0,pad=5);ax.spines['left'].set_visible(False)
        ax.set_title(head,loc='left',fontsize=9,fontweight='bold',pad=11)
    handles=[Rectangle((0,0),1,1,color=NAVY,label=txt(zh,'Singapore','新加坡')),Rectangle((0,0),1,1,color=TEAL,label=txt(zh,'Los Angeles','洛杉矶'))]
    fig.legend(handles=handles,loc='upper center',bbox_to_anchor=(.55,1.015),ncol=2,fontsize=8.5,handlelength=1.2,columnspacing=2)
    fig.text(.55,.015,txt(zh,'Additional successful resolver addresses','新增成功的原 DNS 地址数'),ha='center',fontsize=8.5)
    save(fig,folder,'rule-interactions')

def semantic_continuity(folder,zh,e):
    fig,axs=plt.subplots(1,2,figsize=(7.16,1.92));fig.subplots_adjust(left=.009,right=.992,bottom=.06,top=.92,wspace=.085)
    stable=e['stable_dns64'];assert stable['count']==127 and stable['protocols']=={'h2':95,'dot':32}
    counts=collections.defaultdict(collections.Counter)
    for p in stable['paths']:
        assert p['plain']['rcode']==p['encrypted']['rcode']=='NOERROR'
        assert sum(len(r[2]) for r in p['plain']['answer'] if r[1]=='AAAA')==2 and not p['encrypted']['answer']
        counts[p['key'][1]][p['key'][5]]+=1
    assert {ip:dict(c) for ip,c in counts.items()}=={
      '208.67.220.64':{'h2':24,'dot':8},'208.67.222.64':{'h2':24,'dot':8},
      '2620:119:35::64':{'h2':24,'dot':8},'2620:119:53::64':{'h2':23,'dot':8}}
    ax=axs[0];ax.set_xlim(0,1);ax.set_ylim(4.9,-1.35);ax.axis('off')
    ax.text(0,-1.10,txt(zh,'(a) Public DNS64 paths','(a) 公网 DNS64 路径'),fontsize=9.5,fontweight='bold')
    headers=[(0,txt(zh,'Original IP','原 DNS 地址'),'left'),(.49,'H2','right'),(.62,'DoT','right'),(.82,txt(zh,'AAAA: plain → enc.','AAAA：明文 → 加密'),'center')]
    for x,t,ha in headers:ax.text(x,-.2,t,ha=ha,va='center',fontsize=8.5)
    ax.axhline(.2,color=INK,lw=.6)
    for y,ip in enumerate(stable['originals'],start=1):
        ax.text(0,y,ip,fontsize=8.5,va='center');ax.text(.49,y,str(counts[ip]['h2']),ha='right',va='center',fontsize=8.5);ax.text(.62,y,str(counts[ip]['dot']),ha='right',va='center',fontsize=8.5)
        ax.text(.82,y,'2 → 0',ha='center',va='center',fontsize=9,color=GOLD)
        ax.axhline(y+.5,color=GRID,lw=.4)
    ax=axs[1];ax.set_xlim(0,1);ax.set_ylim(4.9,-1.35);ax.axis('off')
    ax.text(0,-1.10,txt(zh,'(b) Native Mac DNS64 controls','(b) Mac 原生 DNS64 对照'),fontsize=9.5,fontweight='bold')
    for x,t,ha in [(0,txt(zh,'Condition','条件'),'left'),(.56,txt(zh,'Transport','传输'),'center'),(.99,txt(zh,'Response (repeats)','应答（重复次数）'),'right')]:ax.text(x,-.2,t,ha=ha,va='center',fontsize=8.5)
    ax.axhline(.2,color=INK,lw=.6)
    cases={c['case']:c for c in e['mac']['cases']}
    labels=txt(zh,['M63  Plain $R_0$','M64  Matched B','M65  DNS64 off','M66  Restored B'],['M63  明文 $R_0$','M64  匹配 B','M65  关闭 DNS64','M66  恢复 B'])
    for y,(cid,lab) in enumerate(zip(['M63','M64','M65','M66'],labels),start=1):
        qs=cases[cid]['test_results']['v4only'];assert len(qs)==3 and all(q['rcode']=='0' for q in qs)
        n=sum(any(a.startswith('64:ff9b:') for a in q['addresses']) for q in qs)
        assert n==(0 if cid=='M65' else 3)
        ax.text(0,y,lab,fontsize=8.5,va='center');ax.text(.56,y,'UDP/53' if y==1 else 'H2',ha='center',va='center',fontsize=8.5)
        ax.text(.99,y,txt(zh,'Synthesized (3/3)','合成地址（3/3）') if n else 'NODATA (3/3)',ha='right',va='center',fontsize=8.5,color=INK if n else GOLD)
        ax.axhline(y+.5,color=GRID,lw=.4)
    save(fig,folder,'semantic-continuity')

def authority_control(folder,zh,e):
    fig,ax=plt.subplots(figsize=(3.5,1.48));fig.subplots_adjust(left=.28,right=.985,bottom=.11,top=.72)
    cases={c['case']:c for c in e['mac']['cases']};ids=[f'M{i}' for i in range(51,57)]
    for x,c in enumerate(ids):
        mode=cases[c]['condition']['authority']
        for y,allowed in enumerate([mode in ['both','ip'],mode in ['both','domain']]):
            ax.scatter(x,y,s=20,facecolors=NAVY if allowed else WHITE,edgecolors=NAVY if allowed else '#B8C2C9',linewidth=.7)
        doh=cases[c]['transports'].get('doh',0)==3
        ax.text(x,2,'H2' if doh else txt(zh,'Plain','明文'),ha='center',va='center',fontsize=8.5,color=TEAL if doh else GOLD)
    ax.set_xticks(range(6),ids,fontsize=8.5);ax.xaxis.tick_top();ax.tick_params(axis='x',pad=8)
    ax.set_yticks([0,1,2],txt(zh,['Accept $R_0$','Accept T','Query path'],['接受 $R_0$','接受 T','查询路径']),fontsize=8.5);ax.set_ylim(2.5,-.5);ax.set_xlim(-.5,5.5);clean(ax)
    ax.axhline(1.5,color=GRID,lw=.6)
    save(fig,folder,'authority-control')

def run(language='en'):
    zh=language=='zh';configure(zh);folder=ROOT/'zh'/'figures' if zh else ROOT/'figures'
    summary=load('summary.json');failure=load('los-angeles-failure-analysis.json');e=load('extensions/figure-evidence.json')
    sets={p:set().union(*(set((DATA/f'ipv{v}-{p}-success-union.txt').read_text().split()) for v in [4,6])) for p in PROFILES}
    assert len(set.union(*sets.values()))==112 and len(set.intersection(*sets.values()))==45
    assert sum(summary['cross_vantage'][f'ipv{v}']['current_svcb_cohort']['union'] for v in [4,6])==351897
    stages=['discovery_ineligible','no_compatible_service','missing_original_ip_san','connect_or_handshake_failure','certificate_chain_failure','target_name_mismatch','http_or_dns_failure','pass']
    totals={p:{k:sum(failure['stages'][f'ipv{v}'][p].get(k,0) for v in [4,6]) for k in stages} for p in PROFILES}
    assert all(sum(v.values())==348769 for v in totals.values())
    methodology(folder,zh,e);groups=overlap(folder,zh,sets);failure_stages(folder,zh,totals)
    interventions(folder,zh,e);interactions(folder,zh,e);semantic_continuity(folder,zh,e);authority_control(folder,zh,e)
    if not zh:
        dot=set((DATA/'windows-dot-all-success.txt').read_text().split())
        derived={'cohort':351897,'success':{p:len(s) for p,s in sets.items()},'any_success':112,'all_success':45,
          'exclusive_membership':[{'profiles':[p for p,b in zip(PROFILES,bits) if b],'count':n} for bits,n in groups],
          'los_angeles_stage_counts':totals,'windows_dot':len(dot),'macos_doh_plus_tested_dot_union':len(sets['macos']|dot),
          'macos_doh_plus_tested_dot_intersection':len(sets['macos']&dot),'macos_dot_additions':sorted(dot-sets['macos']),
          'success_percent':{p:100*len(s)/351897 for p,s in sets.items()},
          'input_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in DATA.glob('*') if f.is_file() and f.name!='derived.json'}}
        (DATA/'derived.json').write_text(json.dumps(derived,indent=2),encoding='utf-8')
    manifest={'language':language,'vector_pdf_count':7,'source_evidence_sha256':hashlib.sha256((DATA/'extensions/figure-evidence.json').read_bytes()).hexdigest(),
              'figures':{p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in folder.glob('*.pdf')},
              'minimum_font_pt':8.5}
    (folder/'figure-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(f'Rebuilt 7 vector PDF figures and PNG previews ({language}) in {folder}')

if __name__=='__main__':
    import sys
    run(sys.argv[1] if len(sys.argv)>1 else 'en')
