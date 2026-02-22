# Mobi

## Overview

Mobi is a mobile-first social networking and directory platform for repair professionals in India. It connects technicians, teachers/trainers, spare parts suppliers, and job providers in the repair industry. The app features a social feed with posts (repair work, jobs, training, supplier info), a professional directory with search/filter, job listings, direct messaging/chat, and user profiles. It's built as an Expo React Native app with an Express backend, targeting iOS, Android, and web platforms.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend (Expo / React Native)

- **Framework**: Expo SDK 54 with React Native 0.81, using expo-router for file-based routing with typed routes
- **Navigation**: Tab-based layout with role-specific tabs. Customer: Find (directory), Buy & Sell (marketplace), Profile. Teacher/Supplier: Feed, Content/Products, Post, Directory, Profile. Technician/JobProvider: Feed, Shop (marketplace), Post, Directory, Profile. Plus stack screens for onboarding, chats list, individual chat, reels, and upload-reel
- **State Management**: React Context (`lib/context.tsx`) provides global app state (profile, posts, jobs, conversations) with server polling every 5 seconds
- **Data Flow**: All data (posts, jobs, profiles, conversations) is fetched from the Express backend API. AsyncStorage is used only for local profile caching and onboarding state
- **Styling**: Dark theme only (both light and dark color schemes map to the same dark palette in `constants/colors.ts`). Uses Inter font family loaded via `@expo-google-fonts/inter`
- **Key Libraries**: expo-image for optimized images, expo-image-picker for photo selection, expo-haptics for tactile feedback, react-native-keyboard-controller for keyboard handling, react-native-reanimated for animations, react-native-gesture-handler

### Backend (Express)

- **Server**: Express 5 running on Node.js (`server/index.ts`)
- **Routes**: `server/routes.ts` has full API routes prefixed with `/api` for profiles, posts, jobs, conversations, messages, OTP, and image uploads
- **File Storage**: Bunny.net Storage for images and videos. Files are uploaded via Bunny Storage API (PUT with AccessKey), served through Bunny CDN at `Mobistorage.b-cdn.net`. Falls back to local `uploads/` directory if Bunny is unavailable. Videos use disk-based multer + stream upload to avoid memory issues with large files (up to 500MB)
- **Image Upload**: Uses multer memory storage for images, uploads to Bunny.net. Endpoint: `POST /api/upload`
- **CORS**: Configured to allow Replit dev/deployment domains and localhost origins
- **Static Serving**: In production, serves a built static web bundle. In development, proxies to Metro bundler
- **Build Pipeline**: Custom build script (`scripts/build.js`) handles Expo web static builds. Server is bundled with esbuild for production

### Database (PostgreSQL via Drizzle)

- **ORM**: Drizzle ORM with PostgreSQL dialect, configured in `drizzle.config.ts`
- **Schema**: Full schema in `shared/schema.ts` with tables: profiles, posts, jobs, conversations, messages, reels, products, orders, subscription_settings, courses, course_chapters, course_videos, course_enrollments, dubbed_videos, payments
- **Schema Validation**: Uses drizzle-zod for generating Zod schemas from Drizzle table definitions
- **Database driver**: Uses `pg` package (not neon-http) for Drizzle ORM connection

### Data Model

- **UserProfile** (profiles table): id, name, phone, role, skills[], city, state, experience, shopName, avatar, bio, sellType, teachType, shopAddress, gstNumber, aadhaarNumber, panNumber
- **UserRole**: technician | teacher | supplier | job_provider | customer
- **Post** (posts table): id, userId, userName, userRole, text, images[] (as JSON), category (repair|job|training|supplier), likes[] (as JSON), comments[] (as JSON)
- **Job** (jobs table): id, userId, userName, title, description, city, state, skills[] (as JSON), type (full_time|part_time|contract), salary
- **Conversation** (conversations table): id, participant1Id/Name/Role, participant2Id/Name/Role, lastMessage, lastMessageAt
- **ChatMessage** (messages table): id, conversationId, senderId, senderName, text, image, createdAt
- **Reel** (reels table): id, userId, userName, userAvatar, title, description, videoUrl, thumbnailUrl, likes[] (as JSON), views, createdAt
- **Product** (products table): id, userId, userName, userRole, userAvatar, title, description, price, category (course|tutorial|ebook|spare_part|tool|component), images[] (as JSON), city, state, contactPhone, deliveryInfo, inStock, likes[] (as JSON), views, createdAt
- **Course** (courses table): id, teacherId, teacherName, teacherAvatar, title, description, price, coverImage, category (software_repair|hardware_repair|mobile_repair|laptop_repair|ac_repair|tv_repair|other), language, demoDuration (default 60s), accessDays (default 365), totalVideos, totalDuration, enrollmentCount, rating, isPublished, createdAt
- **CourseChapter** (course_chapters table): id, courseId, title, description, sortOrder, createdAt
- **CourseVideo** (course_videos table): id, courseId, chapterId, title, description, videoUrl, thumbnailUrl, duration, sortOrder, isDemo, createdAt
- **CourseEnrollment** (course_enrollments table): id, courseId, studentId, studentName, studentPhone, teacherId, status, paymentStatus, expiresAt, createdAt
- **Payment** (payments table): id, razorpayOrderId, razorpayPaymentId, razorpaySignature, courseId, studentId, studentName, studentPhone, teacherId, amount, currency, status (created|paid|failed), enrollmentId, createdAt
- **DubbedVideo** (dubbed_videos table): id, videoId, courseId, language, dubbedVideoUrl, status (processing|completed|failed), createdAt
- **LiveClass** (live_classes table): id, courseId, teacherId, teacherName, title, description, scheduledAt, duration, status (scheduled|live|completed|cancelled), meetingUrl, createdAt
- **CourseNotice** (course_notices table): id, courseId, teacherId, teacherName, title, message, createdAt
- **AppSetting** (app_settings table): id, key (unique), value, updatedAt. Used for admin-configurable app settings like live_url and web_tools_url

### API Endpoints

- `POST /api/auth/check-phone` - Check if phone number is registered, returns profile if exists
- `POST /api/auth/register` - Register new user profile
- `GET/POST /api/profiles` - List all or create/update profile
- `GET/POST/DELETE /api/posts` - CRUD for posts
- `POST /api/posts/:id/like` - Toggle like on post
- `POST /api/posts/:id/comment` - Add comment to post
- `GET/POST/DELETE /api/jobs` - CRUD for jobs
- `GET/POST/DELETE /api/conversations` - CRUD for conversations
- `GET/POST /api/messages` - Get and send messages
- `GET /api/messages/:conversationId/since/:timestamp` - Poll for new messages
- `POST /api/upload` - Upload image file (multipart/form-data, field: "image")
- `GET /api/gcs/:folder/:filename` - Serve file via Bunny.net proxy (legacy route)
- `GET /api/files/:folder/:filename` - Serve file via Bunny.net proxy
- `POST /api/upload-video` - Upload video file to Bunny.net (multipart/form-data, field: "video", max 500MB)
- `GET/POST/DELETE /api/reels` - CRUD for reels (only teachers can upload)
- `POST /api/reels/:id/like` - Toggle like on reel
- `GET/POST/DELETE /api/products` - CRUD for products/listings (teachers: courses/tutorials/ebooks, suppliers: spare parts/tools/components)
- `GET /api/products/:id` - Get single product detail (increments views)
- `POST /api/products/:id/like` - Toggle like on product
- `POST /api/otp/send` and `POST /api/otp/verify` - SMS OTP via Twilio
- `GET /api/subscription-settings` - Get subscription settings for all roles (auto-creates defaults)
- `PATCH /api/subscription-settings/:role` - Update subscription toggle/amount/period for a role
- `GET/POST/DELETE /api/courses` - CRUD for courses (teachers only for creation)
- `GET /api/courses/:id` - Get course with chapters and videos
- `GET/POST/DELETE /api/courses/:courseId/chapters` - CRUD for course chapters
- `GET/POST/DELETE /api/courses/:courseId/chapters/:chapterId/videos` - CRUD for chapter videos
- `POST /api/courses/:courseId/enroll` - Enroll student in course (legacy, direct enrollment)
- `GET /api/enrollments/check` - Check enrollment status (courseId + studentId)
- `POST /api/payments/create-order` - Create Razorpay payment order for course enrollment
- `POST /api/payments/verify` - Verify Razorpay payment signature and enroll student
- `GET /api/payments/checkout` - Serve Razorpay checkout HTML page (WebView)
- `GET /api/payments` - List payment records (filter by studentId, teacherId, courseId)
- `GET /api/chat/can-contact/:teacherId` - Check if student can message teacher (requires active enrollment)
- `POST /api/dubbing/start` - Start AI dubbing for a video to target language
- `GET /api/dubbing/status/:videoId` - Get dubbing status/availability per language
- `GET /api/dubbing/languages` - List supported dubbing languages
- `GET/POST /api/courses/:courseId/live-classes` - CRUD for live classes
- `PATCH /api/live-classes/:id/status` - Update live class status (go live, complete, cancel)
- `DELETE /api/live-classes/:id` - Delete a live class
- `GET /api/courses/:courseId/students` - List enrolled students for a course
- `GET/POST /api/courses/:courseId/notices` - CRUD for course notices
- `DELETE /api/notices/:id` - Delete a notice
- `GET /api/app-settings` - Get all app settings as key-value object
- `GET /api/app-settings/:key` - Get a single app setting value
- `PUT /api/app-settings/:key` - Create or update an app setting

### App Flow

1. First launch → Onboarding screen: phone first → check if registered → auto-login OR continue with name/role/selfie(non-customers only)/skills or sellType or teachType/businessDocs(supplier+teacher)/location
2. Supplier onboarding: "What do you sell" (Spare Parts/Accessories/Tools/Software) + shop address + GST + Aadhaar + PAN
3. Teacher onboarding: "What do you teach" (Software/Hardware) + Aadhaar + PAN
4. Profile stored locally + synced to server → redirected to main tab navigator
5. Feed tab shows posts filtered by category, fetched from server
6. Directory tab shows real registered users from server with role filtering
7. Create tab for new posts with image upload (images uploaded to server)
8. Jobs tab for job listings from server
9. Profile tab for viewing/editing profile
10. Chat accessible from directory cards and conversation list, images uploaded to server before sending
11. Admin panel at /admin restricted to phone 8179142535 only (ADMIN_PHONE constant in lib/types.ts)
12. Admin panel shows user avatars, phone numbers, business details (expandable cards), subscription controls per role
13. Teacher course creation: create-course screen with course details, chapter management (folders), video uploads per chapter (500MB max), demo video toggles, publish/unpublish
14. Course browsing: courses screen lists all published courses, course-detail shows chapters/videos with enrollment, marketplace has "Browse Courses" banner
15. Custom video player: course-player screen with expo-av, custom controls (play/pause, seek, skip 10s, volume), 1-minute demo preview limit for non-enrolled users
16. AI dubbing: language selector in video player triggers Google Cloud AI pipeline (Speech-to-Text → Translation → TTS → FFmpeg audio mixing), dubbed videos stored on Bunny.net and tracked in dubbed_videos table
17. Chat/call restrictions: technicians can only chat with teachers if they have an active course enrollment

### Development & Deployment

- **Dev**: Two processes needed — `expo:dev` for Metro bundler and `server:dev` for Express backend
- **Production Build**: `expo:static:build` creates web bundle, `server:build` bundles server, `server:prod` serves everything
- **Database Migrations**: `db:push` uses drizzle-kit to push schema to PostgreSQL
- **Patches**: Uses patch-package (postinstall script)

## External Dependencies

- **PostgreSQL**: Required via DATABASE_URL environment variable for Drizzle ORM (provisioned by Replit)
- **AsyncStorage**: `@react-native-async-storage/async-storage` for local profile caching
- **Expo Services**: Font loading, image picking, haptics, crypto (UUID generation)
- **Twilio SMS**: SMS OTP delivery via Twilio (`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`)
- **AI Dubbing Pipeline** (`server/dubbing.ts`): Google Cloud Speech-to-Text for transcription, Google Cloud Translation API for translation, Google Cloud Text-to-Speech for speech synthesis (Wavenet voices for all 12 Indian languages), FFmpeg for audio mixing with original video. Supports: Hindi, Tamil, Telugu, Kannada, Malayalam, Bengali, Marathi, Gujarati, Punjabi, Odia, Urdu, English
- **Razorpay Payment Gateway**: Course enrollment payments via Razorpay (2.36% fees). Backend creates orders, serves checkout HTML page, verifies payment signatures. Frontend uses WebView (mobile) or popup window (web) for checkout. Supports UPI, cards, net banking, wallets.
- **Environment Variables**: `DATABASE_URL` (PostgreSQL), `REPLIT_DEV_DOMAIN` / `REPLIT_DOMAINS` (CORS/Expo), `EXPO_PUBLIC_DOMAIN` (client API URL), `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`, `SESSION_SECRET`, `BUNNY_STORAGE_API_KEY` (Bunny.net Storage password), `BUNNY_STORAGE_ZONE_NAME` (Bunny.net storage zone), `BUNNY_STORAGE_REGION` (Bunny.net region, default 'de'), `GCS_SERVICE_ACCOUNT_KEY` (Google Cloud service account JSON - used for Speech-to-Text, Translation, and TTS AI dubbing APIs), `RAZORPAY_KEY_ID` (Razorpay API Key ID), `RAZORPAY_KEY_SECRET` (Razorpay API Key Secret)
