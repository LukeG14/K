"use client";

import { useState } from "react";
import {
  ArrowUpRight,
  ChevronDown,
  KeyRound,
  MonitorSmartphone,
  RefreshCcw,
  ShieldCheck,
  Zap,
} from "lucide-react";

/* ============================================================
   Mock data (sin backend, todo escrito en el archivo)
============================================================ */

type Product = {
  id: number;
  name: string;
  category: string;
  status: "Available" | "Sold Out";
};

const PRODUCTS: Product[] = [
  { id: 1, name: "Netflix 4K", category: "Streaming", status: "Available" },
  { id: 2, name: "Spotify Premium", category: "Music", status: "Available" },
  { id: 3, name: "Canva Pro", category: "Design", status: "Available" },
  { id: 4, name: "Crunchyroll", category: "Streaming", status: "Sold Out" },
];

type Faq = { question: string; answer: string };

const FAQS: Faq[] = [
  {
    question: "What happens if my code is invalid?",
    answer: "Contact support immediately with your order ID.",
  },
  {
    question: "Can I use the same code twice?",
    answer: "No, every code is single-use unless specified otherwise.",
  },
  {
    question: "Do you offer refunds?",
    answer: "Read our terms. Refunds only apply if the code is not redeemed.",
  },
];

/* ============================================================
   Navbar
============================================================ */

const Navbar = () => (
  <header className="sticky top-0 z-50 border-b border-white/10 bg-[#0a0b0f]/80 backdrop-blur-md">
    <nav className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
      {/* Logo */}
      <a href="#" className="flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-lime-300 text-black">
          <KeyRound size={18} strokeWidth={2.5} />
        </span>
        <span className="text-lg font-bold tracking-tight">
          Nexa<span className="text-lime-300">Redeem</span>
        </span>
      </a>

      {/* Enlaces centrales */}
      <div className="hidden items-center gap-8 text-sm text-zinc-400 md:flex">
        <a href="#catalog" className="transition-colors hover:text-lime-300">
          Catalog
        </a>
        <a href="#how-to-redeem" className="transition-colors hover:text-lime-300">
          How to Redeem
        </a>
        <a href="#support" className="transition-colors hover:text-lime-300">
          Support
        </a>
      </div>

      {/* Botones derecha */}
      <div className="flex items-center gap-3">
        <a
          href="#"
          className="hidden rounded-lg px-4 py-2 text-sm font-medium text-zinc-300 transition-colors hover:text-white sm:block"
        >
          Sign In
        </a>
        <a
          href="#redeem"
          className="rounded-lg bg-lime-300 px-4 py-2 text-sm font-semibold text-black transition-colors hover:bg-lime-200"
        >
          Redeem Code
        </a>
      </div>
    </nav>
  </header>
);

/* ============================================================
   Hero
============================================================ */

const Hero = () => (
  <section
    id="redeem"
    className="relative overflow-hidden border-b border-white/10"
  >
    {/* Fondo decorativo: grid de puntos */}
    <div
      aria-hidden
      className="pointer-events-none absolute inset-0 opacity-40"
      style={{
        backgroundImage: "radial-gradient(rgba(190,242,100,0.25) 1px, transparent 1px)",
        backgroundSize: "28px 28px",
        maskImage: "radial-gradient(ellipse 60% 60% at 50% 40%, black, transparent)",
        WebkitMaskImage: "radial-gradient(ellipse 60% 60% at 50% 40%, black, transparent)",
      }}
    />

    <div className="relative mx-auto max-w-4xl px-6 py-24 text-center md:py-32">
      <span className="mb-6 inline-flex items-center gap-2 rounded-full border border-lime-300/30 bg-lime-300/10 px-4 py-1.5 text-xs font-medium text-lime-300">
        <Zap size={14} />
        Digital codes, delivered in seconds
      </span>

      <h1 className="text-5xl font-black leading-[1.05] tracking-tight md:text-7xl">
        Unlock Premium.
        <br />
        <span className="text-lime-300">Instantly.</span>
      </h1>

      <p className="mx-auto mt-6 max-w-xl text-lg text-zinc-400">
        Enter your activation code below to claim your digital product.
      </p>

      {/* Contenedor de redención */}
      <div className="mx-auto mt-10 max-w-xl">
        <div className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-white/5 p-4 sm:flex-row sm:items-center sm:rounded-full sm:p-2 sm:pl-6">
          <input
            type="text"
            placeholder="NEXA-XXXX-XXXX"
            className="w-full flex-1 bg-transparent font-mono text-lg tracking-[0.2em] text-white uppercase placeholder:text-zinc-500 focus:outline-none"
          />
          <button
            type="button"
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-lime-300 px-7 py-3.5 font-semibold text-black transition-colors hover:bg-lime-200 sm:rounded-full"
          >
            Unlock Now
            <ArrowUpRight size={18} />
          </button>
        </div>

        <p className="mt-4 text-xs text-zinc-500">
          No account needed for guest redeems.
        </p>
      </div>
    </div>
  </section>
);

/* ============================================================
   Featured Catalog
============================================================ */

const ProductCard = ({ product }: { product: Product }) => {
  const available = product.status === "Available";

  return (
    <article className="group flex flex-col rounded-2xl border border-white/10 bg-white/[0.03] p-5 transition-all hover:-translate-y-1 hover:border-lime-300/40 hover:bg-white/[0.05]">
      <div className="mb-4 flex items-center justify-between">
        <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] font-medium tracking-wide text-zinc-400 uppercase">
          {product.category}
        </span>
        <span className="flex items-center gap-1.5 text-xs font-medium">
          <span
            className={`h-2 w-2 rounded-full ${
              available ? "bg-lime-300" : "bg-zinc-600"
            }`}
          />
          <span className={available ? "text-lime-300" : "text-zinc-500"}>
            {product.status}
          </span>
        </span>
      </div>

      <h3 className="text-xl font-bold tracking-tight">{product.name}</h3>

      <div className="mt-auto pt-6">
        <button
          type="button"
          disabled={!available}
          className="w-full rounded-xl border border-white/15 py-2.5 text-sm font-semibold text-zinc-200 transition-colors group-hover:border-lime-300/50 group-hover:text-lime-300 hover:bg-lime-300/10 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-white/15 disabled:hover:text-zinc-200"
        >
          View Details
        </button>
      </div>
    </article>
  );
};

const FeaturedCatalog = () => (
  <section id="catalog" className="mx-auto max-w-6xl px-6 py-20 md:py-28">
    <div className="mb-10 flex items-end justify-between">
      <h2 className="text-3xl font-bold tracking-tight md:text-4xl">
        Trending on NexaRedeem
      </h2>
      <a
        href="#"
        className="group flex items-center gap-1 text-sm font-medium text-lime-300 transition-colors hover:text-lime-200"
      >
        View full catalog
        <ArrowUpRight
          size={16}
          className="transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
        />
      </a>
    </div>

    <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
      {PRODUCTS.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  </section>
);

/* ============================================================
   The Nexa Way (3 columnas)
============================================================ */

const NEXA_PILLARS = [
  {
    icon: Zap,
    title: "Instant Activation",
    text: "Codes are delivered instantly to your screen. No waiting.",
  },
  {
    icon: ShieldCheck,
    title: "Verified Quality",
    text: "Every product is tested before the code is generated.",
  },
  {
    icon: RefreshCcw,
    title: "Smart Warranty",
    text: "If a code fails within the hold time, we replace it automatically.",
  },
];

const TheNexaWay = () => (
  <section
    id="how-to-redeem"
    className="border-y border-white/10 bg-white/[0.02]"
  >
    <div className="mx-auto max-w-6xl px-6 py-20 md:py-28">
      <h2 className="mb-14 text-center text-3xl font-bold tracking-tight md:text-4xl">
        The Nexa Way
      </h2>

      <div className="grid grid-cols-1 gap-12 md:grid-cols-3 md:gap-8">
        {NEXA_PILLARS.map((pillar) => (
          <div key={pillar.title} className="text-center md:text-left">
            <span className="mb-6 inline-flex h-16 w-16 items-center justify-center rounded-2xl border border-lime-300/30 bg-lime-300/10 text-lime-300">
              <pillar.icon size={32} strokeWidth={1.75} />
            </span>
            <h3 className="mb-3 text-xl font-bold tracking-tight">
              {pillar.title}
            </h3>
            <p className="leading-relaxed text-zinc-400">{pillar.text}</p>
          </div>
        ))}
      </div>
    </div>
  </section>
);

/* ============================================================
   Device Compatibility (banner horizontal)
============================================================ */

const DeviceCompatibility = () => (
  <section className="mx-auto max-w-6xl px-6 py-16">
    <div className="flex flex-col items-center gap-6 rounded-2xl border border-lime-300/25 bg-gradient-to-r from-lime-300/10 via-transparent to-lime-300/10 px-8 py-10 text-center sm:flex-row sm:text-left">
      <span className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl bg-lime-300 text-black">
        <MonitorSmartphone size={32} strokeWidth={1.75} />
      </span>
      <p className="text-lg font-medium leading-relaxed text-zinc-200 md:text-xl">
        Works seamlessly on{" "}
        <span className="font-bold text-lime-300">Desktop</span>,{" "}
        <span className="font-bold text-lime-300">Mobile</span>, and{" "}
        <span className="font-bold text-lime-300">Smart TVs</span>. Just log in
        with the credentials provided.
      </p>
    </div>
  </section>
);

/* ============================================================
   FAQ & Support (acordeón)
============================================================ */

const FaqItem = ({
  faq,
  isOpen,
  onToggle,
}: {
  faq: Faq;
  isOpen: boolean;
  onToggle: () => void;
}) => (
  <div className="border-b border-white/10">
    <button
      type="button"
      onClick={onToggle}
      className="flex w-full items-center justify-between gap-4 py-5 text-left"
    >
      <span className="font-semibold text-zinc-100">{faq.question}</span>
      <ChevronDown
        size={20}
        className={`shrink-0 text-lime-300 transition-transform duration-200 ${
          isOpen ? "rotate-180" : ""
        }`}
      />
    </button>
    <div
      className={`grid transition-all duration-200 ${
        isOpen ? "grid-rows-[1fr] pb-5 opacity-100" : "grid-rows-[0fr] opacity-0"
      }`}
    >
      <p className="overflow-hidden text-zinc-400">{faq.answer}</p>
    </div>
  </div>
);

const FaqSupport = () => {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <section id="support" className="border-t border-white/10 bg-white/[0.02]">
      <div className="mx-auto grid max-w-6xl grid-cols-1 gap-12 px-6 py-20 md:grid-cols-[1fr_1.5fr] md:py-28">
        {/* Columna izquierda */}
        <div>
          <h2 className="text-4xl font-black tracking-tight md:text-5xl">
            Need Help?
          </h2>
          <p className="mt-4 max-w-xs text-zinc-400">
            Quick answers about redeeming, codes and warranties. Still stuck?
            Our team replies in minutes.
          </p>
        </div>

        {/* Columna derecha: acordeón */}
        <div className="border-t border-white/10">
          {FAQS.map((faq, index) => (
            <FaqItem
              key={faq.question}
              faq={faq}
              isOpen={openIndex === index}
              onToggle={() => setOpenIndex(openIndex === index ? null : index)}
            />
          ))}
        </div>
      </div>
    </section>
  );
};

/* ============================================================
   Footer
============================================================ */

const FOOTER_LINKS = ["Privacy Policy", "Terms of Service", "Contact"];

const Footer = () => (
  <footer className="border-t border-white/10">
    <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-6 px-6 py-10 sm:flex-row">
      {/* Logo */}
      <a href="#" className="flex items-center gap-2">
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-lime-300 text-black">
          <KeyRound size={15} strokeWidth={2.5} />
        </span>
        <span className="font-bold tracking-tight">
          Nexa<span className="text-lime-300">Redeem</span>
        </span>
      </a>

      {/* Copyright */}
      <p className="text-sm text-zinc-500">© 2026 NexaRedeem</p>

      {/* Enlaces horizontales */}
      <nav className="flex items-center gap-6 text-sm text-zinc-400">
        {FOOTER_LINKS.map((link) => (
          <a key={link} href="#" className="transition-colors hover:text-lime-300">
            {link}
          </a>
        ))}
      </nav>
    </div>
  </footer>
);

/* ============================================================
   Página
============================================================ */

export default function Page() {
  return (
    <div className="min-h-screen bg-[#0a0b0f] text-zinc-100 antialiased">
      <Navbar />
      <main>
        <Hero />
        <FeaturedCatalog />
        <TheNexaWay />
        <DeviceCompatibility />
        <FaqSupport />
      </main>
      <Footer />
    </div>
  );
}
