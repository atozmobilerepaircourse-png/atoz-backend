import { SpeechClient, protos as speechProtos } from "@google-cloud/speech";
import { TextToSpeechClient, protos as ttsProtos } from "@google-cloud/text-to-speech";
import { v2 } from "@google-cloud/translate";
import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { db } from "./db";
import { dubbedVideos, courseVideos } from "@shared/schema";
import { eq, and } from "drizzle-orm";
import { randomUUID } from "crypto";

const execAsync = promisify(exec);
const { Translate } = v2;

const LANG_MAP: Record<string, { ttsLang: string; voiceName: string; translateLang: string }> = {
  hi: { ttsLang: "hi-IN", voiceName: "hi-IN-Wavenet-A", translateLang: "hi" },
  ta: { ttsLang: "ta-IN", voiceName: "ta-IN-Wavenet-A", translateLang: "ta" },
  te: { ttsLang: "te-IN", voiceName: "te-IN-Standard-A", translateLang: "te" },
  kn: { ttsLang: "kn-IN", voiceName: "kn-IN-Wavenet-A", translateLang: "kn" },
  ml: { ttsLang: "ml-IN", voiceName: "ml-IN-Wavenet-A", translateLang: "ml" },
  bn: { ttsLang: "bn-IN", voiceName: "bn-IN-Wavenet-A", translateLang: "bn" },
  mr: { ttsLang: "mr-IN", voiceName: "mr-IN-Wavenet-A", translateLang: "mr" },
  gu: { ttsLang: "gu-IN", voiceName: "gu-IN-Wavenet-A", translateLang: "gu" },
  pa: { ttsLang: "pa-IN", voiceName: "pa-IN-Wavenet-A", translateLang: "pa" },
  or: { ttsLang: "or-IN", voiceName: "or-IN-Standard-A", translateLang: "or" },
  ur: { ttsLang: "ur-IN", voiceName: "ur-IN-Standard-A", translateLang: "ur" },
  en: { ttsLang: "en-IN", voiceName: "en-IN-Wavenet-A", translateLang: "en" },
};

const BUNNY_STORAGE_API_KEY = process.env.BUNNY_STORAGE_API_KEY || '';
const BUNNY_STORAGE_ZONE_NAME = process.env.BUNNY_STORAGE_ZONE_NAME || '';
const BUNNY_STORAGE_REGION = process.env.BUNNY_STORAGE_REGION || 'sg';
const BUNNY_STORAGE_ENDPOINT = BUNNY_STORAGE_REGION === 'de'
  ? 'https://storage.bunnycdn.com'
  : `https://${BUNNY_STORAGE_REGION}.storage.bunnycdn.com`;
const BUNNY_CDN_URL = `https://Mobistorage.b-cdn.net`;

let speechClient: SpeechClient | null = null;
let ttsClient: TextToSpeechClient | null = null;
let translateClient: InstanceType<typeof Translate> | null = null;

function initClients(): boolean {
  try {
    const serviceAccountKey = process.env.GCS_SERVICE_ACCOUNT_KEY;
    if (!serviceAccountKey) {
      console.log("[Dubbing] Missing GCS credentials for AI services");
      return false;
    }
    const credentials = JSON.parse(serviceAccountKey);
    speechClient = new SpeechClient({ credentials, projectId: credentials.project_id });
    ttsClient = new TextToSpeechClient({ credentials, projectId: credentials.project_id });
    translateClient = new Translate({ credentials, projectId: credentials.project_id } as any);
    console.log("[Dubbing] Google Cloud AI clients initialized");
    return true;
  } catch (err) {
    console.error("[Dubbing] Failed to initialize clients:", err);
    return false;
  }
}

async function downloadVideo(videoUrl: string, destPath: string): Promise<void> {
  if (videoUrl.startsWith('http://') || videoUrl.startsWith('https://')) {
    const response = await fetch(videoUrl);
    if (!response.ok) throw new Error(`Failed to download video: ${response.status}`);
    const buffer = Buffer.from(await response.arrayBuffer());
    fs.writeFileSync(destPath, buffer);
  } else if (videoUrl.startsWith('/api/files/') || videoUrl.startsWith('/api/gcs/')) {
    const filePath = videoUrl.replace(/^\/api\/(files|gcs)\//, '');
    const storageUrl = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${filePath}`;
    const response = await fetch(storageUrl, {
      headers: { 'AccessKey': BUNNY_STORAGE_API_KEY },
    });
    if (!response.ok) throw new Error(`Failed to download from Bunny: ${response.status}`);
    const buffer = Buffer.from(await response.arrayBuffer());
    fs.writeFileSync(destPath, buffer);
  } else if (videoUrl.startsWith('/uploads/')) {
    const localPath = path.join(process.cwd(), videoUrl);
    fs.copyFileSync(localPath, destPath);
  } else {
    throw new Error(`Unknown video URL format: ${videoUrl}`);
  }
}

async function uploadToBunny(localPath: string, storagePath: string): Promise<string> {
  if (!BUNNY_STORAGE_API_KEY || !BUNNY_STORAGE_ZONE_NAME) {
    throw new Error("Bunny.net not configured");
  }
  const buffer = fs.readFileSync(localPath);
  const url = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${storagePath}`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'AccessKey': BUNNY_STORAGE_API_KEY,
      'Content-Type': 'application/octet-stream',
    },
    body: new Uint8Array(buffer),
  });
  if (!response.ok) {
    throw new Error(`Bunny upload failed: ${response.status} ${response.statusText}`);
  }
  return `${BUNNY_CDN_URL}/${storagePath}`;
}

async function extractAudio(videoPath: string, audioPath: string): Promise<void> {
  await execAsync(
    `ffmpeg -y -i "${videoPath}" -vn -acodec pcm_s16le -ar 16000 -ac 1 "${audioPath}"`,
    { timeout: 300000 }
  );
}

async function transcribeAudio(audioPath: string, sourceLang: string): Promise<string> {
  if (!speechClient) throw new Error("Speech client not initialized");

  const audioBytes = fs.readFileSync(audioPath);
  const audio = { content: audioBytes.toString("base64") };

  const langCode = LANG_MAP[sourceLang]?.ttsLang || "hi-IN";

  const fileStats = fs.statSync(audioPath);
  const fileSizeMB = fileStats.size / (1024 * 1024);

  if (fileSizeMB > 10) {
    return await transcribeAudioLong(audioPath, sourceLang);
  }

  const config: speechProtos.google.cloud.speech.v1.IRecognitionConfig = {
    encoding: "LINEAR16" as any,
    sampleRateHertz: 16000,
    languageCode: langCode,
    enableAutomaticPunctuation: true,
    model: "default",
  };

  const [response] = await speechClient.recognize({ audio, config });
  const transcription = response.results
    ?.map((result) => result.alternatives?.[0]?.transcript || "")
    .join(" ")
    .trim();

  return transcription || "";
}

async function transcribeAudioLong(audioPath: string, sourceLang: string): Promise<string> {
  if (!speechClient) throw new Error("Speech client not initialized");

  const tempStoragePath = `temp-audio/${randomUUID()}.wav`;
  const buffer = fs.readFileSync(audioPath);
  const uploadUrl = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${tempStoragePath}`;
  await fetch(uploadUrl, {
    method: 'PUT',
    headers: { 'AccessKey': BUNNY_STORAGE_API_KEY, 'Content-Type': 'application/octet-stream' },
    body: new Uint8Array(buffer),
  });

  const langCode = LANG_MAP[sourceLang]?.ttsLang || "hi-IN";

  const config: speechProtos.google.cloud.speech.v1.IRecognitionConfig = {
    encoding: "LINEAR16" as any,
    sampleRateHertz: 16000,
    languageCode: langCode,
    enableAutomaticPunctuation: true,
    model: "default",
  };

  const audioContent = buffer.toString("base64");
  const [response] = await speechClient.recognize({
    audio: { content: audioContent },
    config,
  });

  const transcription = response.results
    ?.map((result) => result.alternatives?.[0]?.transcript || "")
    .join(" ")
    .trim();

  const deleteUrl = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${tempStoragePath}`;
  await fetch(deleteUrl, {
    method: 'DELETE',
    headers: { 'AccessKey': BUNNY_STORAGE_API_KEY },
  }).catch(() => {});

  return transcription || "";
}

async function translateText(text: string, targetLang: string): Promise<string> {
  if (!translateClient) throw new Error("Translate client not initialized");
  if (!text.trim()) return "";

  const targetCode = LANG_MAP[targetLang]?.translateLang || targetLang;
  const [translation] = await translateClient.translate(text, targetCode);
  return translation;
}

async function textToSpeech(text: string, targetLang: string, outputPath: string): Promise<void> {
  if (!ttsClient) throw new Error("TTS client not initialized");
  if (!text.trim()) throw new Error("No text to synthesize");

  const langConfig = LANG_MAP[targetLang];
  if (!langConfig) throw new Error(`Unsupported language: ${targetLang}`);

  const chunks = splitTextIntoChunks(text, 4500);
  const audioBuffers: Buffer[] = [];

  for (const chunk of chunks) {
    const request: ttsProtos.google.cloud.texttospeech.v1.ISynthesizeSpeechRequest = {
      input: { text: chunk },
      voice: {
        languageCode: langConfig.ttsLang,
        name: langConfig.voiceName,
        ssmlGender: "FEMALE" as any,
      },
      audioConfig: {
        audioEncoding: "MP3" as any,
        speakingRate: 1.0,
        pitch: 0,
      },
    };

    const [response] = await ttsClient.synthesizeSpeech(request);
    if (response.audioContent) {
      audioBuffers.push(Buffer.from(response.audioContent as Uint8Array));
    }
  }

  const combined = Buffer.concat(audioBuffers);
  fs.writeFileSync(outputPath, combined);
}

function splitTextIntoChunks(text: string, maxLen: number): string[] {
  if (text.length <= maxLen) return [text];
  const chunks: string[] = [];
  const sentences = text.split(/(?<=[.!?।])\s+/);
  let current = "";
  for (const sentence of sentences) {
    if ((current + " " + sentence).length > maxLen && current.length > 0) {
      chunks.push(current.trim());
      current = sentence;
    } else {
      current = current ? current + " " + sentence : sentence;
    }
  }
  if (current.trim()) chunks.push(current.trim());
  return chunks;
}

async function mixAudioWithVideo(
  originalVideoPath: string,
  dubbedAudioPath: string,
  outputPath: string
): Promise<void> {
  await execAsync(
    `ffmpeg -y -i "${originalVideoPath}" -i "${dubbedAudioPath}" -c:v copy -map 0:v:0 -map 1:a:0 -shortest "${outputPath}"`,
    { timeout: 600000 }
  );
}

export async function dubVideo(
  videoId: string,
  courseId: string,
  targetLanguage: string,
  sourceLang: string = "hi"
): Promise<{ success: boolean; dubbedVideoUrl?: string; error?: string }> {
  if (!initClients()) {
    return { success: false, error: "Google Cloud AI services not configured" };
  }

  const dubbingId = randomUUID();
  const tempDir = path.join(os.tmpdir(), `dubbing-${dubbingId}`);
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    await db.insert(dubbedVideos).values({
      id: dubbingId,
      videoId,
      courseId,
      language: targetLanguage,
      dubbedVideoUrl: "",
      status: "processing",
      createdAt: Date.now(),
    });

    const [video] = await db
      .select()
      .from(courseVideos)
      .where(eq(courseVideos.id, videoId));

    if (!video) throw new Error("Video not found");

    console.log(`[Dubbing] Starting: ${video.title} -> ${targetLanguage}`);

    const videoPath = path.join(tempDir, "original.mp4");
    const audioPath = path.join(tempDir, "audio.wav");
    const ttsAudioPath = path.join(tempDir, "dubbed.mp3");
    const outputPath = path.join(tempDir, "output.mp4");

    console.log("[Dubbing] Step 1: Downloading video...");
    await downloadVideo(video.videoUrl, videoPath);

    console.log("[Dubbing] Step 2: Extracting audio...");
    await extractAudio(videoPath, audioPath);

    console.log("[Dubbing] Step 3: Transcribing...");
    const transcript = await transcribeAudio(audioPath, sourceLang);
    if (!transcript) throw new Error("Transcription produced no text");
    console.log(`[Dubbing] Transcript (${transcript.length} chars): ${transcript.substring(0, 200)}...`);

    let textForTTS = transcript;
    if (targetLanguage !== sourceLang) {
      console.log(`[Dubbing] Step 4: Translating ${sourceLang} -> ${targetLanguage}...`);
      textForTTS = await translateText(transcript, targetLanguage);
      console.log(`[Dubbing] Translation (${textForTTS.length} chars): ${textForTTS.substring(0, 200)}...`);
    }

    console.log("[Dubbing] Step 5: Generating dubbed speech...");
    await textToSpeech(textForTTS, targetLanguage, ttsAudioPath);

    console.log("[Dubbing] Step 6: Mixing audio with video...");
    await mixAudioWithVideo(videoPath, ttsAudioPath, outputPath);

    console.log("[Dubbing] Step 7: Uploading dubbed video...");
    const storagePath = `dubbed-videos/${courseId}/${videoId}/${targetLanguage}.mp4`;
    const dubbedUrl = await uploadToBunny(outputPath, storagePath);

    await db
      .update(dubbedVideos)
      .set({ dubbedVideoUrl: dubbedUrl, status: "completed" })
      .where(eq(dubbedVideos.id, dubbingId));

    console.log(`[Dubbing] Completed: ${dubbedUrl}`);
    return { success: true, dubbedVideoUrl: dubbedUrl };
  } catch (error: any) {
    console.error(`[Dubbing] Failed:`, error);
    await db
      .update(dubbedVideos)
      .set({ status: "failed" })
      .where(eq(dubbedVideos.id, dubbingId))
      .catch(() => {});
    return { success: false, error: error.message };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

export async function getDubbedVideo(
  videoId: string,
  language: string
): Promise<{ url: string; status: string } | null> {
  const [dubbed] = await db
    .select()
    .from(dubbedVideos)
    .where(and(eq(dubbedVideos.videoId, videoId), eq(dubbedVideos.language, language)));

  if (!dubbed) return null;
  return { url: dubbed.dubbedVideoUrl, status: dubbed.status };
}

export async function getDubbedVideosForVideo(videoId: string): Promise<
  Array<{ language: string; url: string; status: string }>
> {
  const dubbed = await db
    .select()
    .from(dubbedVideos)
    .where(eq(dubbedVideos.videoId, videoId));

  return dubbed.map((d) => ({
    language: d.language,
    url: d.dubbedVideoUrl,
    status: d.status,
  }));
}

export function getSupportedLanguages(): string[] {
  return Object.keys(LANG_MAP);
}
