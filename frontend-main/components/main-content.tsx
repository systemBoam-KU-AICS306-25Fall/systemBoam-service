import { TodaysCVENews } from "@/components/todays-cve-news"
import { LatestCVEUpdates } from "@/components/latest-cve-updates"
import { CVERanking } from "@/components/cve-ranking"

export function MainContent() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left column - wider */}
      <div className="lg:col-span-2 space-y-6">
        <TodaysCVENews />
        <LatestCVEUpdates />
      </div>

      {/* Right column */}
      <div className="lg:col-span-1">
        <CVERanking />
      </div>
    </div>
  )
}
