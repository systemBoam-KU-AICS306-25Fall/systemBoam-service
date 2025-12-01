"use client"

import { useEffect, useState } from "react"
import { Header } from "@/components/header"
import { useParams, useRouter } from "next/navigation"
import { Heart, ArrowLeft } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScoreCard } from "@/components/cve-detail/score-card"
import { TimelineView } from "@/components/cve-detail/timeline-view"
import { EvidenceExplorer } from "@/components/cve-detail/evidence-explorer"
import { PoCPatchSection } from "@/components/cve-detail/poc-patch-section"
import { AIAdvisor } from "@/components/cve-detail/ai-advisor"
import { QuickStatsCard } from "@/components/cve-detail/quick-stats-card"
import { RelatedCVEsList } from "@/components/cve-detail/related-cves-list"
import { RecentActivityLogs } from "@/components/cve-detail/recent-activity-logs"
import { apiGet } from "@/lib/api"

// ---- 백엔드 응답 타입(필요한 필드만) ----
type BasicResp = {
  cve: string
  summary?: string | null
}

type ScoresResp = {
  cve: string
  overall_score: number
  cvss: { base?: number }
  epss?: number | null
  kve?: number | null
  activity?: number | null
}

// 화면에서 쓰기 위한 뷰 모델
type CveViewModel = {
  id: string
  title: string
  status: string
  publishedDate?: string
  severity?: string
  cvssScore: number
  epssScore: number
  kveScore: number
  activityScore: number
}

export default function CVEDetailPage() {
  const params = useParams()
  const router = useRouter()
  const cveId = params.id as string

  const [isFavorited, setIsFavorited] = useState(false)

  const [cveData, setCveData] = useState<CveViewModel | null>(null)
  const [aiSummary, setAiSummary] = useState<string>("")
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  // ---- 최초 로딩 시 백엔드에서 CVE 정보 + 점수 + AI 요약 가져오기 ----
  useEffect(() => {
    if (!cveId) return

    let active = true

    async function load() {
      setLoading(true)
      setError(null)

      try {
        // 1) 기본 정보 + 점수 동시 조회
        const [basic, scores] = await Promise.all([
          apiGet<BasicResp>(`/api/v1/cve/${cveId}/basic`),
          apiGet<ScoresResp>(`/api/v1/cve/${cveId}/scores?window=7d`),
        ])

        if (!active) return

        const cvssBase = scores.cvss?.base ?? 0
        const epss = scores.epss ?? 0
        const kve = scores.kve ?? 0
        const activity = scores.activity ?? 0

        setCveData({
          id: basic.cve,
          // summary가 없으면 placeholder
          title: basic.summary && basic.summary.trim().length > 0 ? basic.summary : "(요약 없음)",
          // 지금은 상태/심각도는 스키마에 없으니 임시값
          status: "Active",
          publishedDate: undefined,
          severity: undefined,
          cvssScore: cvssBase,
          epssScore: epss,
          kveScore: kve,
          activityScore: activity,
        })

        // 2) AI 요약 (템플릿 기반, 현재는 백엔드에서 점수/요약을 이용해 생성)
        try {
          const res = await fetch(`/api/v1/cve/${cveId}/ai-summary?window=7d`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
          })
          if (res.ok) {
            const data = (await res.json()) as { ai_summary?: string }
            if (active) {
              setAiSummary(data.ai_summary ?? "")
            }
          } else {
            if (active) setAiSummary("")
          }
        } catch {
          if (active) setAiSummary("")
        }
      } catch (e) {
        if (active) {
          setError("CVE 상세 정보를 불러오는 중 오류가 발생했습니다.")
        }
      } finally {
        if (active) setLoading(false)
      }
    }

    load()

    return () => {
      active = false
    }
  }, [cveId])

  // 로딩/에러 처리
  if (loading && !cveData) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="container mx-auto px-4 py-6">
          <p className="text-sm text-muted-foreground">CVE 상세 정보를 불러오는 중입니다...</p>
        </main>
      </div>
    )
  }

  if (!cveData) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="container mx-auto px-4 py-6">
          <Button variant="ghost" size="sm" onClick={() => router.back()} className="gap-2 mb-4">
            <ArrowLeft size={16} />
            뒤로가기
          </Button>
          <p className="text-sm text-red-400">
            {error ?? "해당 CVE 정보를 찾을 수 없습니다."}
          </p>
        </main>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-6">
        <div className="mb-4">
          <Button variant="ghost" size="sm" onClick={() => router.back()} className="gap-2">
            <ArrowLeft size={16} />
            뒤로가기
          </Button>
        </div>

        {/* Header Section */}
        <div className="mb-8 pb-6 border-b border-border">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <h1 className="text-foreground font-extrabold text-5xl">{cveData.id}</h1>
                <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-500/10 text-red-500 border border-red-500/20">
                  {cveData.status}
                </span>
              </div>
              <p className="text-lg text-muted-foreground">{cveData.title}</p>
            </div>
            <button
              onClick={() => setIsFavorited(!isFavorited)}
              className="p-2 hover:bg-secondary rounded-lg transition-colors"
            >
              <Heart size={24} className={isFavorited ? "fill-red-500 text-red-500" : "text-muted-foreground"} />
            </button>
          </div>
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-[65%_35%] gap-6">
          {/* Left Column */}
          <div className="space-y-6">
            {/* 여기서부터 CVSS/EPSS/KVE/활동도는 모두 백엔드 점수 사용 */}
            <ScoreCard cveData={cveData} />

            <div className="bg-secondary/30 border border-border rounded-lg p-6">
              <h2 className="text-foreground mb-3 text-lg font-bold">AI 요약</h2>
              <p className="leading-relaxed text-sm text-gray-300">
                {aiSummary && aiSummary.trim().length > 0
                  ? aiSummary
                  : "이 CVE에 대한 AI 요약 정보를 아직 생성하지 못했습니다. 점수와 메타데이터는 상단 카드에서 확인 가능합니다."}
              </p>
            </div>

            <TimelineView />
            <EvidenceExplorer />
            <PoCPatchSection />
            <AIAdvisor />
          </div>

          {/* Right Column */}
          <div className="space-y-6">
            {/* QuickStatsCard는 아직 더미 데이터지만 cveData를 그대로 전달해 둡니다. */}
            <QuickStatsCard cveData={cveData} />
            <RelatedCVEsList />
            <RecentActivityLogs />
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-12 pt-6 border-t border-border text-center text-sm text-muted-foreground">
          <div className="space-y-2">
            <p>CVE 정보 출처: NVD, 보안 커뮤니티</p>
            <div className="flex justify-center gap-6">
              <a href="#" className="hover:text-foreground transition-colors">
                취약점 신고
              </a>
              <a href="#" className="hover:text-foreground transition-colors">
                API 문서
              </a>
              <a href="#" className="hover:text-foreground transition-colors">
                약관
              </a>
              <a href="#" className="hover:text-foreground transition-colors">
                개인정보
              </a>
            </div>
          </div>
        </footer>
      </main>
    </div>
  )
}
