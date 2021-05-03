use portaudio as pa;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::btree_map::BTreeMap;


const FRAMES_PER_BUFFER: u32 = 1024;

type Clip  =Arc<Mutex<Vec<i16>>>;
pub struct ClipPlayer
{
    sample_rate: u32, 
    channels: u8,
    stream: Option<pa::Stream<pa::NonBlocking,pa::Output<i16>>>,
    clips: BTreeMap<String, Clip>,
    // The clip currently being played
    active: Arc<Mutex<Option<Clip>>>
        
}

impl ClipPlayer {
    fn open_audio(&mut self) -> Result<(), pa::error::Error>
    {
	if self.stream.is_some() {return Ok(());}
	
	let pa = pa::PortAudio::new()?;
	let mut settings: pa::OutputStreamSettings<i16> =
            pa.default_output_stream_settings(self.channels as i32,
					      self.sample_rate as f64, 
                                              FRAMES_PER_BUFFER)?;
        // we won't output out of range samples so don't bother clipping them.
        settings.flags = pa::stream_flags::CLIP_OFF;

        let mut sbuffer_pos = 0;
        let mut clip = Arc::new(Mutex::new(Vec::new()));
       
        let active_clone = self.active.clone();
	let channels = self.channels;
        let callback = 
            move |pa::OutputStreamCallbackArgs { buffer, frames, .. }| {
                let mut active = active_clone.lock().unwrap();
                if let Some(ref c) = *active {
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
                    for b in &mut buffer[copy_len..samples] {
                        *b = 0;
                    }
                }
                if sbuffer_pos == sbuffer.len() {pa::Complete} else {pa::Continue}
            };
        self.stream = Some(pa.open_non_blocking_stream(settings, callback)?);
	Ok(())
    }
    
    pub fn new(sample_rate: u32, channels: u8) -> Result<ClipPlayer, pa::error::Error>
    {
	let active : Arc<Mutex<Option<Clip>>>= Arc::new(Mutex::new(None));
	let mut player = ClipPlayer {sample_rate,channels, 
				 stream: None,
				 clips: BTreeMap::new(), 
				 active};
	player.open_audio()?;
        Ok(player)
    }

    pub fn play_clip(&mut self, index: &str) -> Result<(), pa::error::Error>
    {
	self.open_audio()?;
	if let Some(stream) = &mut self.stream {
            match stream.stop() {
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
            stream.start()?;
	}
	Ok(())
    }

    pub fn restart(&mut self) -> Result<(), pa::error::Error>
    {
	self.stream = None; // Close stream
	self.open_audio()
    }
    
    pub fn add_clip(&mut self, index: &str, clip: Vec<i16>) {
        self.clips.insert(index.to_string(), Arc::new(Mutex::new(clip)));
    }

}
