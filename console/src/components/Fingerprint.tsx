import { useEffect, useState } from "react";
import { shortFingerprint } from "../format";

export function Fingerprint({ publicKey }: { publicKey: string }) {
  const [fp, setFp] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    shortFingerprint(publicKey).then((v) => live && setFp(v), () => live && setFp("Unavailable"));
    return () => { live = false; };
  }, [publicKey]);
  return <span>{fp ?? "…"}</span>;
}
