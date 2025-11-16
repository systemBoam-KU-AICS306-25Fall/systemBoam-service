"use client"

import { useState } from "react"
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

export default function CVEDetailPage() {
  const params = useParams()
  const router = useRouter()
  const cveId = params.id as string
  const [isFavorited, setIsFavorited] = useState(false)

  // Mock data - replace with actual API call
  const cveData = {
    id: cveId,
    title: "Critical Vulnerability in Popular Framework",
    description: "A critical vulnerability was discovered in the popular web framework allowing remote code execution.",
    status: "Active",
    publishedDate: "2025-01-15",
    severity: "Critical",
    cvssScore: 9.8,
    epssScore: 0.85,
    kveScore: 0.92,
    activityScore: 8.5,
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
            <ScoreCard cveData={cveData} />

            <div className="bg-secondary/30 border border-border rounded-lg p-6">
              <h2 className="text-foreground mb-3 text-lg font-bold">AI 요약</h2>
              <p className="leading-relaxed text-sm text-gray-300">
                이 취약점은 입력값 검증 부족으로 인해 공격자가 악의적인 페이로드를 실행할 수 있게 합니다. 영향받는
                버전은 3.0 이상 3.5 미만이며, 즉시 패치가 필요합니다. 현재 야생에서 활발히 악용되고 있습니다.
              </p>
            </div>

            <TimelineView />
            <EvidenceExplorer />
            <PoCPatchSection />
            <AIAdvisor />
          </div>

          {/* Right Column */}
          <div className="space-y-6">
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
