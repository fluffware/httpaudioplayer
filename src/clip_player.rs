use portaudio as pa;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::btree_map::BTreeMap;


const FRAMES_PER_BUFFER: u32 = 1024;

type Clip  =Arc<Mutex<Vec<i16>>>;
pub struct ClipPlayer
{
    stream: pa::Stream<pa::NonBlocking,pa::Output<i16>>,
    clips: BTreeMap<String, Clip>,
    // The clip currently being played
    active: Arc<Mutex<Option<Clip>>>
        
}

impl ClipPlayer {
    pub fn new(sample_rate: u32, channels: u8) -> Result<ClipPlayer, pa::error::Error>
    {
        let pa = pa::PortAudio::new()?;
        
        
        let mut settings: pa::OutputStreamSettings<i16> =
            pa.default_output_stream_settings(channels as i32, sample_rate as f64, 
                                              FRAMES_PER_BUFFER)?;
        // we won't output out of range samples so don't bother clipping them.
        settings.flags = pa::stream_flags::CLIP_OFF;

        let mut sbuffer_pos = 0;
        let mut clip = Arc::new(Mutex::new(Vec::new()));
        let active : Arc<Mutex<Option<Clip>>>= Arc::new(Mutex::new(None));
        let active_clone = active.clone();
        let callback = 
            move |pa::OutputStreamCallbackArgs { buffer, frames, .. }| {
                let mut active = active.lock().unwrap();
                if let &Some(ref c) = &*active {
                    clip = c.clone();
                    sbuffer_pos  = 0;
                }
                if active.is_some() {
                    *active = None;
                }
                let sbuffer = clip.lock().unwrap();
    	        let samples = channels as usize * frames;
    	        let copy_len = if sbuffer_pos + samples > sbuffer.len() {
	            sbuffer.len()- sbuffer_pos
	        } else {
	            samples
	        };
	        
    	        buffer[0..copy_len].copy_from_slice(&sbuffer[sbuffer_pos..sbuffer_pos + copy_len]);
	        sbuffer_pos += copy_len;
                if copy_len < samples {
                    for i in copy_len..samples {
                        buffer[i] = 0;
                    }
                }
                if sbuffer_pos == sbuffer.len() {pa::Complete} else {pa::Continue}
            };
        let stream = pa.open_non_blocking_stream(settings, callback)?;
        Ok(ClipPlayer {stream: stream, clips: BTreeMap::new(), active: active_clone})
    }

    pub fn play_clip(&mut self, index: &str) -> Result<(), pa::error::Error>
    {
        match self.stream.stop() {
            Ok(_) => {},
            Err(pa::Error::StreamIsStopped) => {},
            Err(e) => return Err(e)
        }
        match self.clips.get(index) {
            Some(clip) => {
                let mut active = self.active.lock().unwrap();
                *active = Some(clip.clone())
            },
            None => return Ok(())
        }
        self.stream.start()?;
        Ok(())
    }

    pub fn add_clip(&mut self, index: &str, clip: Vec<i16>) {
        self.clips.insert(index.to_string(), Arc::new(Mutex::new(clip)));
    }

}
