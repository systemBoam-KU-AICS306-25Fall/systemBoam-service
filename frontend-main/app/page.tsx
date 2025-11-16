import { Header } from "@/components/header"
import { SearchSection } from "@/components/search-section"
import { MainContent } from "@/components/main-content"
import { EnvironmentFeedCTA } from "@/components/environment-feed-cta"

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-6 space-y-8">
        <SearchSection />
        <MainContent />
        <EnvironmentFeedCTA />
      </main>
    </div>
  )
}
