import { backend } from '@/lib/backend';
export function POST(request: Request) { return backend(request, '/v1/scans'); }
